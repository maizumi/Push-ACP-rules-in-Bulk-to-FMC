<h2>Youtube video</h2> <br>

[![Watch the video](https://img.youtube.com/vi/1nPtBRju6Ag/0.jpg)](https://youtu.be/1nPtBRju6Ag)

<H1>IMPORTANT NOTICE</H1>
1.Please prepare objects before using this app. If FMC doesn't have objects using this app, then you will get an error.<br>
2.If you got an error, check objects in csv file and FMC objects. Also security zones must be matched with csv file and FMC configured.<br>
#If you'd like to deploy hundreds of objects, then you can use my "Push-Objects-in-Bulk-to-FMC" app in different repository.

# Push-ACP-rules-in-Bulk-to-FMC <br>
#Push ACP access rules in bulk to FMC through web app(flask) <br>
#This app tested in FMC 7.0.1. However it should be worked in other versions too.<br>

Basically, once you have deployed in your environment, you access to flask web site and enter FMC ip address, login credentials, ACP name, then upload csv file which include ACP access rules you want to add, then click "ENTER". It will be automatically make a ACP with ACP name you enter, then add rules based on csv file you uploaded.<br>
Rules should be 1 to 1000. You might get an error if you try to add more than 1000 rules.

This python code works in Python3 <br>
Because this web app is based on Flask framework, folders and hierarchy are important. <br>
 <br>
Hierarchy should be like below. <br>
 <br>
FMC_AC_RULE_BULK.py <br>
L templates <br>
  L index2.html <br>
L static <br>
  L fpr.png << this can be whatever you want to display on index2.html<br> 
L uploads <br>
  L {uploaded file will be saved here} <br>
 <br>
for libraries, please install using requirements.txt <br>
pip install -r requirements.txt <br>
