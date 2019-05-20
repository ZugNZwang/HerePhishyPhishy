# HerePhishyPhishy
# Eric Holguin
# Mohammad Hossain
# Cyber Infrastructre Defense
# Final Project

import os
import re
import sys
import pickle
import datetime
import tldextract
import numpy as np
import pandas as pd
import ipaddress as ip
from os.path import splitext
from urllib.parse import urlparse
from sklearn.metrics import accuracy_score
from sklearn import cross_validation, tree


Suspicious_TLD= [ 'country','kim','science','gq','work','ninja','xyz','date',
                  'faith','zip','racing','cricket','win','space','accountant',
                  'realtor','top','stream','christmas','gdn','mom','pro','men']

Suspicious_Domain=['luckytime.co.kr','mattfoll.eu.interia.pl',
                   'trafficholder.com','dl.baixaki.com.br',
                   'bembed.redtube.comr','tags.expo9.exponential.com',
                   'deepspacer.com','funad.co.kr','trafficconverter.biz']

# Count number of dots
def countdots(url):
    return url.count('.')

# Count number of delimeters
def countdelim(url):
    count = 0
    delim=[';','_','?','=','&']
    for each in url:
        if each in delim:
            count = count + 1

    return count

# Check if the IP addr present in the url
def isip(uri):
    try:
        if ip.ip_address(uri):
            return 1
    except:
        return 0

# Check the presence of hyphens
def isPresentHyphen(url):
    return url.count('-')

# Check the presence of @
def isPresentAt(url):
    return url.count('@')

# Redirect double slash
def isPresentDSlash(url):
    return url.count('//')

# Count of Subdirectories
def countSubDir(url):
    return url.count('/')

# Return the filename extension from url, or ''.
def get_ext(url):
    root, ext = splitext(url)
    return ext

# Count the subdomains
def countSubDomain(subdomain):
    if not subdomain:
        return 0
    else:
        return len(subdomain.split('.'))

# Count the number of Queries
def countQueries(query):
    if not query:
        return 0
    else:
        return len(query.split('&'))

featureSet = pd.DataFrame(columns=('url','Dot Count','Hyphen Count','URL length','@ Count',\
'// Count','Subdir Count','Subdomain Count','Domain Length','Query Count','has IP','Suspicious TLD',\
'Suspicious Domain','label'))

def getFeatures(url, label):
    result = []
    url = str(url)

    # Add the url to feature set
    result.append(url)

    # Parse the URL and extract the domain information
    path = urlparse(url)
    ext = tldextract.extract(url)

    # Counting the number of dots in the subdomain
    result.append(countdots(ext.subdomain))

    # Check for hyphen in domain
    result.append(isPresentHyphen(path.netloc))

    # Length of URL
    result.append(len(url))

    # Check for @ in the url
    result.append(isPresentAt(path.netloc))

    # Check for double slash
    result.append(isPresentDSlash(path.path))

    # Count number of subdir
    result.append(countSubDir(path.path))

    # Number of sub domains
    result.append(countSubDomain(ext.subdomain))

    # Length of the domain name
    result.append(len(path.netloc))

    # Count number of queries
    result.append(len(path.query))

    # If IP address is being used as the URL
    result.append(isip(ext.domain))

    # Check for suspicious TLD
    result.append(1 if ext.suffix in Suspicious_TLD else 0)

    # Check for suspicious domain
    result.append(1 if '.'.join(ext[1:]) in Suspicious_Domain else 0 )

    result.append(str(label))
    return result

def model():
    # Read in Dataset
    df = pd.read_csv("dataset2.csv")
    df = df.sample(frac=1).reset_index(drop=True)

    for i in range(len(df)):
        features = getFeatures(df["URL"].loc[i], df["Label"].loc[i])
        featureSet.loc[i] = features

    X = featureSet.drop(['url','label'],axis=1).values
    y = featureSet['label'].values

    X_train, X_test, y_train, y_test = cross_validation.train_test_split(X, y ,test_size=0.2)

    clf = tree.DecisionTreeClassifier(max_depth=10)
    model = clf.fit(X_train,y_train)
    score = clf.score(X_test,y_test)

    # save the model to disk
    filename = 'model.pkl'
    pickle.dump(model, open(filename, 'wb'))

    #return clf

def predictURL(url):
    #model()
    filename = 'model.pkl'
    clf = pickle.load(open(filename, 'rb'))

    result = pd.DataFrame(columns=('url','Dot Count','Hyphen Count','URL length','@ Count',\
    '// Count','Subdir Count','Subdomain Count','Domain Length','Query Count','has IP','Suspicious TLD',\
    'Suspicious Domain','label'))

    results = getFeatures(url, '1')
    result.loc[0] = results
    result = result.drop(['url','label'],axis=1).values
    #print(clf.predict(result))
    if(clf.predict(result) == '1'):
        print("\u001b[31:0mLikely Phishing URL Detected!")
    elif(clf.predict(result) == '0'):
        print("\u001b[36:0mUnlikely Phishing URL!")
