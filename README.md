# HerePhishyPhishy

Phishing is a prime example of social engineering and can cause a lot of harm to an end user or organization and it is an attack that can be difficult to defend against. This project aims to build an anti-phishing tool that will help prevent such phishing attacks.

# Implementation

The application was built using python 3.6 in addition to some valuable python libraries and the help of the [**PhishTank API**](https://www.phishtank.com/).

We used the _PyInquirer_ library in order to build a simple to use command line interface for the user, adding colors that makes it easy for the user to tell the difference between commands and program output.

Using the _Scapy_ library we were able to log the incoming queries from port 53, which logs DNS queries. This helped us and the user to see what URLs your system makes, and we can manually check if they look suspicious.

We created a developer account with **PhishTank** that allowed us to use their free API in order to check phishing URLs against their database. We send a POST request, formatted in _JSON_ and we then parse the response to check whether the URL we sent is in their database or not and whether it has been flagged as phishing or not.

Finally, we used the _sklearn_ library which provides the algorithms necessary for machine learning detection. We used the dataset downloaded from PhishTank, which included 7000+ URLs, each with their own label, 1 as phishing or 0 as not. We then defined the features we deemed important, such as:

- Presence of **@**
- Presence of **//**
- Count of **.** in the URL
- Number of delimeters
- If the **IP address** is found inside the URL
- Presence of **-**
- Count of subdirectories
- Filename extension
- Subdomain
- Count of queries

Each feature was setup as a method that could parse a URL to extract the information, this then allowed us to create a dataframe of the extracted features and then pass this to the decision tree classifier. Roughly half of our data was labeled as a phishing URL and the other half as not. With a decision tree with a maximum depth of 10 we used a training sample of 80% and a testing
sample of 20%. Our accuracy calculation was **89.6%** This was a good score, but we found there still exist false positives and false negatives when testing certain URLs.


# User Instructions

**_This was tested and ran on MacOS Mojave_**

To install the application on your own system first download it from GitHub and install the python libraries required.

`# git clone https://github.com/ZugNZwang/HerePhishyPhishy.git`
`# cd HerePhishyPhishy`
`# pip install -r requirements.txt`

Then you will be able to run the application. Please note that sudo privileges are needed in order to log the DNS traffic.

`# sudo python3 HerePhishyPhishy `

You will see the main menu:

![alt-text](https://github.com/ZugNZwang/HerePhishyPhishy/blob/master/images/MainMenu.png)

Using the arrow keys the user is able to select a menu option and then press enter to proceed.

### DNS Logging Option:
Selecting this option allows the user to see the traffic on port 53, any DNS queries made will be listed. This can help the user see if there exists any suspicious traffic. If a URL looks suspicious to the user they can then check that URL to see if it is a phishing attack. The user must know what network interface they are using.

#### Example of DNS Logging:

![alt-text](https://github.com/ZugNZwang/HerePhishyPhishy/blob/master/images/DNS.png)


### Check URL Option:
Selecting this option allows the user to check a URL of their choosing. The user will be asked to type out the URL they would like to check. The application sends an API request to the PhishTank website which checks to see if the URL already exists on their database. If the API request returns false it means the URL is not a phishing scheme and the user is notified. If it is true then the user is alerted. The user should enter the full URL.

#### Checking https://Google.com:

![alt-text](https://github.com/ZugNZwang/HerePhishyPhishy/blob/master/images/CheckURLPass.png)

#### Checking a known Phishing URL:

![alt-text](https://github.com/ZugNZwang/HerePhishyPhishy/blob/master/images/CheckURLFail.png)

### ML Detection Option:

Selecting this option allows the user to check a URL of their choosing using machine learning prediction. The user will be asked to type out the URL they would like to check. The application then uses the pre-existing model, that was trained on dataset of existing phishing URLs, to then return its prediction on whether the URL could possibly be a Phishing URL or whether it is safe.
**_The user should enter the full URL for better results._**

#### Checking http://twitter.com:

![alt-text](https://github.com/ZugNZwang/HerePhishyPhishy/blob/master/images/MLDetectionPass.png)

#### Checking a known Phishing URL:

![alt-text](https://github.com/ZugNZwang/HerePhishyPhishy/blob/master/images/MLDetectionFail.png)

# Immediate Future Work
Future work that can soon be implemented would be the auto-check feature. Our goal with this project was to be able to allow the user to run this application in the background and have our PhishTank API in addition to the machine learning prediction running alongside the DNS logging. This would mean that each time a DNS query is logged it would be checked against our methods and any time something seems suspicious the user could be notified. Another immediate implementation that could be done would be logging other incoming or outgoing connections from other ports. Finally, we could add more important features to our decision tree which could help improve the accuracy of the detector.

# Long Term Future Work
Future work that can be implemented in the long run would be improving the already implemented features, using different machine learning methods that may improve the accuracy and precision. We would also need to use additional phishing mitigation techniques, this could possibly include checking website contents for spam, possibly using Convolutional Neural Networks to check the appearance of actual legitimate websites and those that are fake phishing sites. Looking into detecting phishing email, SMS, or even VoIP. Another implementation that would provide value would be mitigating injection attacks. Ideally we would want our application thorough enough to detect multiple different type of phishing attacks and provide an all in one platform that users could use.
