from flask import Flask, jsonify, abort
from flask import request as rq
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt, get_jti
from sqlalchemy import desc, func, and_, or_
from pyfcm import FCMNotification
from datetime import datetime, timedelta, date, time
from pytz import timezone, UTC
from statistics import mean
from configparser import ConfigParser
from email_validator import validate_email, EmailNotValidError
from flask_bcrypt import Bcrypt
import requests
import sys
import threading
import math
import random
import redis
import json
from exponent_server_sdk import (
    DeviceNotRegisteredError,
    PushClient,
    PushMessage,
    PushServerError,
    PushTicketError,
)
from requests.exceptions import ConnectionError, HTTPError


# Create the app
app = Flask(__name__, static_url_path='/static')
bcrypt = Bcrypt()

# Get our config info
config = ConfigParser()
config.read("/etc/webconfigs/carebit/config.txt")
# config.read("config.txt")

db_uri = config.get("db", "mysql_db_uri")
jwt_key = config.get("jwt", "jwt_key")
fitBitcarebitBase64ID = config.get("fitbit", "carebitBase64ID")
fitBitclientID = config.get("fitbit", "clientId")
firebaseApiKey = config.get("firebase", "apiKey")
mailgunAPIKey = config.get("mailgun", "apiKey")
mailgunURL = config.get("mailgun", "mailgunURL")
redisPassword = config.get("redis", "password")
subsVerify = config.get("verify", "subVerify")

ACCESS_EXPIRES = timedelta(days=31)
REFRESH_EXPIRES = timedelta(days=31)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['MYSQL_DATABASE_CHARSET'] = 'utf8mb4'
app.config['JWT_SECRET_KEY'] = jwt_key
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
db = SQLAlchemy(app)
jwt = JWTManager(app)

revokedStore = redis.StrictRedis(host='localhost', port=6379,
                                 password=redisPassword, db=0,
                                 decode_responses=True)

# For handling threads created by Fitbit calling /fitbit-notifications
# subscriptionLock = threading.Lock()

###############################################################################
#                      Class models for the datbase tables                    #
###############################################################################


class users(db.Model):
    """
    User database table
    """
    __tablename__ = "users"
    userID = db.Column(db.Integer, primary_key = True, unique = True)
    firstName = db.Column(db.String(255))
    lastName = db.Column(db.String(255))
    phone = db.Column(db.String(255))
    email = db.Column(db.String(255))
    password = db.Column(db.String(255))
    messageToken = db.Column(db.String(255))
    mobilePlatform = db.Column(db.String(255))
    authPhase = db.Column(db.Integer)

    def __init__(self, userID, firstName, lastName, phone, email, password,
                 messageToken, mobilePlatform, authPhase):
        self.userID = userID
        self.firstName = firstName
        self.lastName = lastName
        self.phone = phone
        self.email = email
        self.password = password
        self.messageToken = messageToken
        self.mobilePlatform = mobilePlatform
        self.authPhase = authPhase

    def toJSON(self):
        """
        Create a serializable representation of our data, so we can return
        JSON from our DB queries.
        """
        return {
            "userID": self.userID,
            "firstName": self.firstName,
            "lastName": self.lastName,
            "phone": self.phone,
            "email": self.email,
            "messageToken": self.messageToken,
            "mobilePlatform": self.mobilePlatform,
            "authPhase": self.authPhase
        }


class caregivee(db.Model):
    """
    Caregivee database table 
    """
    __tablename__ = "caregivee"
    caregiveeID = db.Column(db.String(255), primary_key = True, unique = True)
    fitbitAccessToken = db.Column(db.String(65535))
    accessTokenExpiresOn = db.Column(db.DateTime)
    fitbitRefreshToken = db.Column(db.String(65535))
    monitoring = db.Column(db.Integer)
    recordHR = db.Column(db.Integer)
    recordSteps = db.Column(db.Integer)
    recordDeviceData = db.Column(db.Integer)
    sleep = db.Column(db.Integer)
    doNotDisturb = db.Column(db.Integer)
    healthProfile = db.Column(db.Integer)
    subscriptionID = db.Column(db.Integer)
    userID = db.Column(db.Integer)
    physName = db.Column(db.String(255))
    physPhone = db.Column(db.String(255))
    physStreet = db.Column(db.String(255))
    physCity = db.Column(db.String(255))
    physState = db.Column(db.String(255))
    physZip = db.Column(db.String(255))
    pendingRequestCount = db.Column(db.Integer)

    def __init__(self, caregiveeID, fitbitAccessToken, accessTokenExpiresOn,
                 fitbitRefreshToken, subscriptionID, userID):
        self.caregiveeID = caregiveeID
        self.fitbitAccessToken = fitbitAccessToken
        self.accessTokenExpiresOn = accessTokenExpiresOn
        self.fitbitRefreshToken = fitbitRefreshToken
        self.monitoring = 1
        self.recordHR = 1
        self.recordSteps = 1
        self.recordDeviceData = 1
        self.sleep = 0
        self.doNotDisturb = 0
        self.healthProfile = None
        self.subscriptionID = subscriptionID
        self.userID = userID
        self.physName = None
        self.physPhone = None
        self.physStreet = None
        self.physCity = None
        self.physState = None
        self.physZip = None
        self.pendingRequestCount = 0


    def toJSON(self):
        """
        Create a serializable representation of our data, so we can return
        JSON from our DB queries.
        """
        return {
            "caregiveeID": self.caregiveeID,
            "monitoring": self.monitoring,
            "recordHR": self.recordHR,
            "recordSteps": self.recordSteps,
            "recordDeviceData": self.recordDeviceData,
            "sleep": self.sleep,
            "doNotDisturb": self.doNotDisturb,
            "healthProfile": self.healthProfile,
            "userID": self.userID,
            "physName": self.physName,
            "physPhone": self.physPhone,
            "physStreet": self.physStreet,
            "physCity": self.physCity,
            "physState": self.physState,
            "physZip": self.physZip,
            "pendingRequestCount": self.pendingRequestCount
        }


class caregiver(db.Model):
    """
    Caregiver database table
    """
    __tablename__ = "caregiver"
    caregiverID = db.Column(db.Integer, primary_key = True, unique = True)
    userID = db.Column(db.Integer)
    pendingRequestCount = db.Column(db.Integer)
    optNumber = db.Column(db.String(255))

    def __init__(self, caregiverID, userID):
        self.caregiverID = caregiverID
        self.userID = userID
        self.pendingRequestCount = 0
        self.optNumber = None

    def toJSON(self):
        """
        Create a serializable representation of our data, so we can return
        JSON from our DB queries.
        """
        return {
            "caregiverID": self.caregiverID,
            "userID": self.userID,
            "pendingRequestCount": self.pendingRequestCount,
            "optNumber": self.optNumber
        }


class thresholds(db.Model):
    """
    Threshold database table
    """
    __tablename__ = "thresholds"
    caregiveeID = db.Column(db.String(255), primary_key = True, unique = True)
    lowHRThreshold = db.Column(db.Integer)
    highHRThreshold = db.Column(db.Integer)
    currentDayLowHR = db.Column(db.Integer)
    currentDayHighHR = db.Column(db.Integer)
    stepThreshold = db.Column(db.Integer)
    timeWithoutHRThreshold = db.Column(db.Integer)
    timeWithoutStepsThreshold = db.Column(db.Integer)

    def __init__(self, caregiveeID, lowHRThreshold, highHRThreshold, stepThreshold):
        self.caregiveeID = caregiveeID
        self.lowHRThreshold = lowHRThreshold
        self.highHRThreshold = highHRThreshold
        self.stepThreshold = stepThreshold

    def setCurrentLow(self, rate):
        self.currentDayLowHR = rate

    def setCurrentHigh(self, rate):
        self.currentDayHighHR = rate

    def toJSON(self):
        """
        Create a serializable representation of our data, so we can return
        JSON from our DB queries.
        """
        return {
            "caregiveeID": self.caregiveeID,
            "lowHRThreshold": self.lowHRThreshold,
            "highHRThreshold": self.highHRThreshold,
            "stepThreshold": self.stepThreshold,
            "timeWithoutHRThreshold": self.timeWithoutHRThreshold,
            "timeWithoutStepsThreshold": self.timeWithoutStepsThreshold
        }


class alerts(db.Model):
    """
    Alerts database table
    Alert type can be:
    lowHeartRateAlert, highHeartRateAlert, noHeartRateAlert, noStepsAlert, 
    tooManyStepsAlert, noSyncAlert, batteryAlert, requestAccepted, chatMessage
    """
    __tablename__ = "alerts"
    alertID = db.Column(db.Integer, primary_key = True, unique = True)
    caregiveeID = db.Column(db.String(255))
    dateTime = db.Column(db.DateTime)
    title = db.Column(db.String(255))
    body = db.Column(db.String(255))
    alertType = db.Column(db.String(255))
    ok = db.Column(db.Integer)
    hasCaregiver = db.Column(db.Integer)
    caregiverID = db.Column(db.String(255))

    def __init__(self, alertID, caregiveeID, dateTime, title, body, alertType, hasCaregiver, caregiverID):
        self.alertID = alertID
        self.caregiveeID = caregiveeID
        self.dateTime = dateTime
        self.title = title
        self.body = body
        self.alertType = alertType
        self.ok = 0
        self.hasCaregiver = hasCaregiver
        self.caregiverID = caregiverID

    def markOK(self):
        self.ok = 1

    def toJSON(self):
        """
        Create a serializable representation of our data, so we can return
        JSON from our DB queries.
        """
        return {
            "alertID": self.alertID,
            "caregiveeID": self.caregiveeID,
            "dateTime": datetime.strftime(self.dateTime, "%Y-%m-%d %H:%M:%S"),
            "title": self.title,
            "body": self.body,
            "alertType": self.alertType,
            "ok": self.ok,
            "hasCaregiver": self.hasCaregiver,
            "caregiverID": self.caregiverID
        }


class fitbit(db.Model):
    """
    Fitbit device database table
    """
    __tablename__ = "fitbit"
    deviceID = db.Column(db.String(255), primary_key = True)
    caregiveeID = db.Column(db.String(255), unique = True)
    deviceVersion = db.Column(db.String(255))
    battery = db.Column(db.String(255))
    deviceType = db.Column(db.String(255))
    lastSyncTime = db.Column(db.DateTime)
    lastSyncAlert = db.Column(db.String(255))
    intervalTime = db.Column(db.DateTime)

    def __init__(self, deviceID, caregiveeID, deviceVersion, battery,
                 deviceType, lastSyncTime, lastSyncAlert, intervalTime):
        self.deviceID = deviceID
        self.caregiveeID = caregiveeID
        self.deviceVersion = deviceVersion
        self.battery = battery
        self.deviceType = deviceType
        self.lastSyncTime = lastSyncTime
        self.lastSyncAlert = lastSyncAlert
        self.intervalTime = intervalTime

    def toJSON(self):
        """
        Create a serializable representation of our data, so we can return
        JSON from our DB queries.
        """
        return {
            "deviceID": self.deviceID,
            "caregiveeID": self.caregiveeID,
            "deviceVersion": self.deviceVersion,
            "battery": self.battery,
            "deviceType": self.deviceType,
            "lastSyncTime": datetime.strftime(self.lastSyncTime, "%Y-%m-%d %H:%M:%S"),
            "lastSyncAlert": self.lastSyncAlert,
            "intervalTime": datetime.strftime(self.intervalTime, "%Y-%m-%d %H:%M:%S")
        }


class heartRate(db.Model):
    """
    Heart rate tracking database table
    """
    __tablename__ = "heartRate"
    measurementID = db.Column(db.Integer, primary_key = True, unique = True)
    caregiveeID = db.Column(db.String(255), unique = True)
    date = db.Column(db.DateTime)
    timeMeasured = db.Column(db.DateTime)
    restingRate = db.Column(db.Integer)
    minHR = db.Column(db.Integer)
    maxHR = db.Column(db.Integer)
    average = db.Column(db.Integer)
    intervalTime = db.Column(db.DateTime)

    def __init__(self, measurementID, caregiveeID, date, timeMeasured,
                 restingRate, minHR, maxHR, average, intervalTime):
        self.measurementID = measurementID
        self.caregiveeID = caregiveeID
        self.date = date
        self.timeMeasured = timeMeasured
        self.restingRate = restingRate
        self.minHR = minHR
        self.maxHR = maxHR
        self.average = average
        self.intervalTime = intervalTime

    # def setAverage(self, average):
    #     self.average = average
    # def setMinMax(self, minHR, maxHR):
    #     self.minHR = minHR
    #     self.maxHR = maxHR

    def toJSON(self):
        """
        Create a serializable representation of our data, so we can return
        JSON from our DB queries.
        """
        return {
            "measurementID": self.measurementID,
            "caregiveeID": self.caregiveeID,
            "date": str(self.date),
            "timeMeasured": str(self.timeMeasured),
            "restingRate": self.restingRate,
            "average": self.average,
            "minHR": self.minHR,
            "maxHR": self.maxHR,
            "intervalTime": datetime.strftime(self.intervalTime, "%Y-%m-%d %H:%M:%S")
        }


class steps(db.Model):
    """
    Step tracking database table
    """
    __tablename__ = "steps"
    measurementID = db.Column(db.Integer, primary_key = True, unique = True)
    caregiveeID = db.Column(db.String(255), unique = True)
    date = db.Column(db.DateTime)
    currentDayTotal = db.Column(db.Integer)
    timeMeasured = db.Column(db.DateTime)
    hourlyTotal = db.Column(db.Integer)
    hourlyTime = db.Column(db.DateTime)
    noStepTime = db.Column(db.DateTime)
    intervalTime = db.Column(db.DateTime)

    def __init__(self, measurementID, caregiveeID, date, currentDayTotal,
                 timeMeasured, hourlyTotal, hourlyTime, noStepTime, intervalTime):
        self.measurementID = measurementID
        self.caregiveeID = caregiveeID
        self.date = str(date)
        self.currentDayTotal = currentDayTotal
        self.timeMeasured = timeMeasured
        self.hourlyTotal = hourlyTotal
        self.hourlyTime = hourlyTime
        self.noStepTime = noStepTime
        self.intervalTime = intervalTime

    def toJSON(self):
        """
        Create a serializable representation of our data, so we can return
        JSON from our DB queries.
        """
        return {
            "measurementID": self.measurementID,
            "caregiveeID": self.caregiveeID,
            "date": str(self.date),
            "currentDayTotal": self.currentDayTotal,
            "timeMeasured": str(self.timeMeasured),
            "hourlyTime": str(self.hourlyTime),
            "hourlyTotal": self.hourlyTotal,
            "noStepTime": datetime.strftime(self.noStepTime, "%Y-%m-%d %H:%M:%S"),
            "intervalTime": datetime.strftime(self.intervalTime, "%Y-%m-%d %H:%M:%S")
        }


class messages(db.Model):
    """
    Quick chat messages table
    """
    __tablename__ = "messages"
    messageID = db.Column(db.Integer, primary_key = True, unique = True)
    recipient = db.Column(db.Integer)
    sender = db.Column(db.Integer)
    timeStamp = db.Column(db.DateTime)
    messageBody = db.Column(db.Text)
    messageRead = db.Column(db.Integer)

    def __init__(self, messageID, recipient, sender, timeStamp, messageBody, messageRead):
        self.messageID = messageID
        self.recipient = recipient
        self.sender = sender
        self.timeStamp = timeStamp
        self.messageBody = messageBody
        self.messageRead = messageRead

    def toJSON(self):
        """
        Create a serializable representation of our data, so we can return
        JSON from our DB queries.
        """
        return {
            "messageID": self.messageID,
            "recipient": self.recipient,
            "sender": self.sender,
            "timeStamp": datetime.strftime(self.timeStamp, "%Y-%m-%d %H:%M:%S"),
            "messageBody": self.messageBody,
            "messageRead": self.messageRead,
        }

class connections(db.Model):
    
    __tablename__ = "connections"
    requestID = db.Column(db.Integer, primary_key = True, unique = True)
    caregiveeID = db.Column(db.String(255))
    caregiverID = db.Column(db.Integer)
    status = db.Column(db.String(255))
    sender = db.Column(db.String(255))
    caregiveeDefault = db.Column(db.Integer)
    caregiverDefault = db.Column(db.Integer)
    lowHRThreshold = db.Column(db.Integer)
    highHRThreshold = db.Column(db.Integer)
    currentDayLowHR = db.Column(db.Integer)
    currentDayHighHR = db.Column(db.Integer)
    stepThreshold = db.Column(db.Integer)
    timeWithoutHRThreshold = db.Column(db.Integer)
    timeWithoutStepsThreshold = db.Column(db.Integer)
    healthProfile = db.Column(db.Integer)
    sendNoSync = db.Column(db.Integer)
    sendNoBattery = db.Column(db.Integer)

    def __init__(self, requestID, caregiveeID, caregiverID, status, sender, caregiveeDefault, caregiverDefault,
                lowHRThreshold, highHRThreshold, currentDayLowHR, currentDayHighHR, stepThreshold, timeWithoutHRThreshold,
                timeWithoutStepsThreshold, healthProfile):
        self.requestID = requestID
        self.caregiveeID = caregiveeID
        self.caregiverID = caregiverID
        self.status = status
        self.sender = sender
        self.caregiveeDefault = caregiveeDefault
        self.caregiverDefault = caregiverDefault
        self.lowHRThreshold = lowHRThreshold
        self.highHRThreshold = highHRThreshold
        self.currentDayLowHR = currentDayLowHR
        self.currentDayHighHR = currentDayHighHR
        self.stepThreshold = stepThreshold
        self.timeWithoutHRThreshold = timeWithoutHRThreshold
        self.timeWithoutStepsThreshold = timeWithoutStepsThreshold
        self.healthProfile = healthProfile
        self.sendNoSync = 1
        self.sendNoBattery = 1

    def toJSON(self):
        
        return {
            "requestID": self.requestID,
            "caregiveeID": self.caregiveeID,
            "caregiverID": self.caregiverID,
            "status": self.status,
            "sender": self.sender,
            "caregiveeDefault": self.caregiveeDefault,
            "caregiverDefault": self.caregiverDefault,
            "lowHRThreshold": self.lowHRThreshold,
            "highHRThreshold": self.highHRThreshold,
            "currentDayLowHR": self.currentDayLowHR,
            "currentDayHighHR": self.currentDayHighHR,
            "stepThreshold": self.stepThreshold,
            "timeWithoutHRThreshold": self.timeWithoutHRThreshold,
            "timeWithoutStepsThreshold": self.timeWithoutStepsThreshold,
            "healthProfile": self.healthProfile,
            "sendNoSync": self.sendNoSync,
            "sendNoBattery": self.sendNoBattery
        }

###############################################################################
#                               Helper Methods                                #
###############################################################################



def requestAccessAndRefreshTokens(code, origin):
    """
    First time request for access and refresh tokens
    If origin is web login, we'll use the web redirect uri, if from app, use
    the app uri.
    Arguments taken: authorization code
    Returns: Fitbit JSON packet
    Response from Fitbit looks like this:
    {
        "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0MzAzNDM3MzUsInNjb3BlcyI6Indwcm8gd2xvYyB3bnV0IHdzbGUgd3NldCB3aHIgd3dlaSB3YWN0IHdzb2MiLCJzdWIiOiJBQkNERUYiLCJhdWQiOiJJSktMTU4iLCJpc3MiOiJGaXRiaXQiLCJ0eXAiOiJhY2Nlc3NfdG9rZW4iLCJpYXQiOjE0MzAzNDAxMzV9.z0VHrIEzjsBnjiNMBey6wtu26yHTnSWz_qlqoEpUlpc",
        "expires_in": 3600,
        "refresh_token": "c643a63c072f0f05478e9d18b991db80ef6061e4f8e6c822d83fed53e5fafdd7",
        "token_type": "Bearer",
        "user_id": "26FWFL"
    }
    """

    if origin == "web":
        redirect_uri = "https://www.carebit.xyz/"
    elif origin == "app":
        redirect_uri = "carebit://callback"
    
    carebitBase64ID = fitBitcarebitBase64ID
    authHeader = "Basic " + carebitBase64ID
    requestHeaders = {
        "Content-Type": "application/x-www-form-urlencoded", "Authorization": authHeader}
    requestDict = {"clientId": fitBitclientID, "grant_type": "authorization_code",
                   "redirect_uri": redirect_uri, "code": code}
    
    print("https://api.fitbit.com/oauth2/token", requestHeaders, requestDict)

    responseFromFitbit = requests.post(
        "https://api.fitbit.com/oauth2/token", headers=requestHeaders, data=requestDict)
        
    print("RESPONSE FROM FITBIT IN REQUEST METHOD: " + responseFromFitbit.text)

    if responseFromFitbit.status_code == 200:
        return responseFromFitbit.json()
    else:
        return None


def refreshAccessToken(cgvee):
    """
    Refresh access token when it expires
    Arguments taken: caregivee DB object model
    Returns: Fitbit JSON packet
    Response from Fitbit looks like this:
    {
        "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0MzAzNDM3MzUsInNjb3BlcyI6Indwcm8gd2xvYyB3bnV0IHdzbGUgd3NldCB3aHIgd3dlaSB3YWN0IHdzb2MiLCJzdWIiOiJBQkNERUYiLCJhdWQiOiJJSktMTU4iLCJpc3MiOiJGaXRiaXQiLCJ0eXAiOiJhY2Nlc3NfdG9rZW4iLCJpYXQiOjE0MzAzNDAxMzV9.z0VHrIEzjsBnjiNMBey6wtu26yHTnSWz_qlqoEpUlpc",
        "expires_in": 3600,
        "refresh_token": "c643a63c072f0f05478e9d18b991db80ef6061e4f8e6c822d83fed53e5fafdd7",
        "token_type": "Bearer",
        "user_id": "26FWFL"
    }
    """

    carebitBase64ID = fitBitcarebitBase64ID
    authHeader = "Basic " + carebitBase64ID
    requestHeaders = {
        "Content-Type": "application/x-www-form-urlencoded", "Authorization": authHeader}
    requestDict = {"grant_type": "refresh_token",
                   "refresh_token": cgvee.fitbitRefreshToken}

    responseFromFitbit = requests.post(
        "https://api.fitbit.com/oauth2/token", headers=requestHeaders, data=requestDict)

    print(responseFromFitbit.text)

    if responseFromFitbit.status_code == 200:
        return responseFromFitbit.json()
    else:
        return None


def getHeartRateData(ownerId, accessToken):
    """
    Pull heart rate data from Fitbit and add to the data base.
    First, we need to check the database to see the last time that we
    recorded a measurement. So then we can get the latest values from that 
    time until the current time. 
    Arguments: The caregivee's Fitbit ID and access token
    """

    # Get the last HR record, and also get the caregivee's threshold record
    # to see their current high and low heart rates. We also want to keep track
    # of whether or now the last record's date is different from current date
    today1 = datetime.now(timezone("US/Eastern")).date()

    lastRecord = heartRate.query.filter(heartRate.caregiveeID == ownerId, heartRate.date == today1).first()
    cgvee = caregivee.query.get(ownerId)
    print(lastRecord)
    dateDiff = False

    # Set our start and end times for our request. If there's no records in the
    # database, we'll just start at midnight
    if lastRecord == None or lastRecord.date < today1:
        startTime = str(datetime.min.time())
        dateDiff = True
    else:
        startTime = str(lastRecord.timeMeasured + timedelta(minutes=.1) - timedelta(minutes=60))

    endTime = datetime.now(timezone("US/Eastern")).strftime("%H:%M:%S")
    today = datetime.now(timezone("US/Eastern")).strftime('%Y-%m-%d')

    # URL Format:
    # Intraday: https://api.fitbit.com/1/user/-/activities/heart/date/2018-11-05/1d/1min/time/00:00/00:01.json

    authHeader = "Bearer " + accessToken
    requestHeaders = {
        "Content-Type": "application/x-www-form-urlencoded", "Authorization": authHeader}
    urlBase = "https://api.fitbit.com/1/user/"
    url = urlBase + ownerId + "/activities/heart/date/" + today + \
        "/1d/1min/time/" + startTime + "/" + endTime + ".json"

    print("URL: " + url)

    responseFromFitbit = requests.get(url, headers=requestHeaders)

    print("HEART RATE RESPONSE FROM FITBIT: " + responseFromFitbit.text)

    responseFromFitbit = responseFromFitbit.json()

    info = responseFromFitbit.get("activities-heart-intraday")
    # restingHeartRateGroup = responseFromFitbit.get("activities-heart")
    # restingHeartRate = [d["value"] for d in responseFromFitbit.get("activities-heart")]
    

    # The JSON packet we get is a list of dicts, but we only need the values,
    # not the keys. Here's an example response:
    #
    # "dataset": [
    #  {
    #    "time": "15:23:00",
    #    "value": 77
    #  },
    #  {
    #    "time": "15:24:00",
    #    "value": 82
    #  }]

    try:
        times = [d["time"] for d in info.get("dataset")]
        values = [d["value"] for d in info.get("dataset")]
    except:
        print("Error occured. Check access privileges.")
    finally:
        # print("times: ", times)
        # print("values: ", values)

        actualTime = datetime.now(timezone("US/Eastern"))
        if lastRecord != None:
            intervalDate = (lastRecord.intervalTime).date()
            timeDiff1 = (lastRecord.intervalTime).time()
        else:
            timeDiff1 = datetime.min.time()
        timeDiff2 = (actualTime).time()
        timeDiff2 = datetime.combine(date.min, timeDiff2) - datetime.min
        timeDiff1 = datetime.combine(date.min, timeDiff1) - datetime.min
        print("TimeDiff2 = {} TimeDiff1 = {}".format(timeDiff2, timeDiff1))

        intervalDiffTime = (timeDiff2 - timeDiff1).total_seconds() / 3600
        print(f"IntervalDiffTime {intervalDiffTime}")

        # prevent duplicate entry
        if len(values) != 0:
            thisTime = datetime.now(timezone("US/Eastern")).time()
            thisTime = time(
                thisTime.hour, thisTime.minute, thisTime.second)  

            if lastRecord != None and str(lastRecord.date) == today:
                if min(values) < lastRecord.minHR:
                    lastRecord.minHR = min(values)
                if max(values) > lastRecord.maxHR:
                    lastRecord.maxHR = max(values)
                lastRecord.average = (lastRecord.average + (sum(values) / len(values))) / 2
                lastRecord.timeMeasured = thisTime

                lastRecord.restingRate = values[len(values) - 1]
                db.session.commit()
            else:
                minTime = datetime.min
                # print(f"last record date/type: {lastRecord.date}/{type(lastRecord.date)}, today/type = {today}/{type(today)}")
                newEntry = heartRate(None, ownerId, today, thisTime, values[len(values) - 1], min(values), max(values), ((min(values) + max(values)) / 2), minTime)
                db.session.add(newEntry)
                db.session.commit()

            for row in connections.query.filter(connections.caregiveeID == ownerId).all():
                row.currentDayLowHR = min(values)
                row.currentDayHighHR = max(values)

                db.session.commit()
            

        # Getting all instances of the caregivee being in connections. Update but make sure later when giving data,
        # the caregiver has permission to see it.
        for row in connections.query.filter(connections.caregiveeID == ownerId).all():
            
            # Get caregivers's user id
            grabUser = caregiver.query.filter(caregiver.caregiverID == row.caregiverID).first()
            caregiverId = grabUser.caregiverID

            # Checks to see if we should send heart rate not recorded notification
            if (len(values) == 0):
                # Since we store the date and times in the database separately, we'll
                # create a combined datetime object from the columns in the database.
                # And since our datetime.now().time() object also includes miliseconds
                # (and the database values do not), we'll do the same thing with the
                # current time and date so we can compare the properly
                
                currentDate = datetime.now(timezone("US/Eastern")).date()
                currentTime = datetime.now(timezone("US/Eastern")).time()
                currentTime = time(
                    currentTime.hour, currentTime.minute, currentTime.second)
                currentDateTime = datetime.combine(currentDate, currentTime)

                if lastRecord != None:
                    lastTime = (datetime.min + lastRecord.timeMeasured).time()
                    lastDateTime = datetime.combine(lastRecord.date, lastTime)
                else:
                    lastTime = currentTime
                    lastDateTime = datetime.combine(currentDate, lastTime)

                print("*** LAST TIME: " + str(lastDateTime) + " *****")
                print("*** CURRENT TIME: " + str(currentDateTime) + " *****")

                timeDiffSeconds = (currentDateTime - lastDateTime).total_seconds()
                timeDiffHours = int(timeDiffSeconds/3600.0)

                # Make sure the caregivee isn't sleeping or in do not disturb mode. No need
                # to send this notifications if so
                if row.timeWithoutHRThreshold != None:
                    if cgvee.doNotDisturb != 1 and cgvee.sleep != 1:
                        if (timeDiffHours >= row.timeWithoutHRThreshold and timeDiffHours <= 24 and (intervalDiffTime >= 1 or intervalDate != today1)):
                            lastRecord.intervalTime = actualTime
                            db.session.commit()
                            try:
                                sendPushNotification(ownerId, "Heart Rate Not Recorded", "'s heart rate hasn't been recorded for approximately " + str(
                                timeDiffHours) + " hours", "noHeartRateAlert", caregiverId)
                            except Exception as e:
                                print("Push notification error HR (time without HR threshold): {}".format(str(e)))
                        elif(timeDiffHours > 24 and (intervalDiffTime >= 1 or intervalDate != today)):
                            lastRecord.intervalTime = actualTime
                            db.session.commit()
                            try:
                                sendPushNotification(ownerId, "Heart Rate Not Recorded",
                                                "'s heart rate hasn't been recorded in over a day", "noHeartRateAlert", caregiverId)
                            except Exception as e:
                                print("Push notification error HR (timeDiffHours > 24): {}".format(str(e)))

            else:
                # This prevents us from sending mulitple heart rate exceeds threshold alerts
                notificationValue = 0
                if row.lowHRThreshold != None and row.highHRThreshold != None:
                    if (row.lowHRThreshold != None and min(values) < row.lowHRThreshold):
                        notificationValue = min(values)
                    elif (row.highHRThreshold != None and min(values) > row.highHRThreshold):
                        notificationValue = max(values)
                else:
                    notificationValue = min(values)
                
                # Send alert with value
                # Make sure the caregivee isn't sleeping or in do not disturb mode, and
                # that the caregiver hasn't turned off alerts for this metric. No need
                # to send this notifications if so
                if row.lowHRThreshold != None and row.highHRThreshold != None and lastRecord.restingRate != None :
                    if cgvee.doNotDisturb != 1 and cgvee.sleep != 1 and cgvee.recordHR == 1:
                        if (lastRecord.restingRate < row.lowHRThreshold):
                            try:
                                sendPushNotification(ownerId, "Low Heart Rate", "'s heart rate is " +
                                                str(lastRecord.restingRate) + " BPM", "lowHeartRateAlert", caregiverId)
                            except Exception as e:
                                print("Push notification error HR (low hr threshold): {}".format(str(e)))
                        elif (lastRecord.restingRate > row.highHRThreshold):
                            try:
                                sendPushNotification(ownerId, "High Heart Rate", "'s heart rate is " + str(
                                lastRecord.restingRate) + " BPM", "highHeartRateAlert", caregiverId)
                            except Exception as e:
                                print("Push notification error HR (high hr threshold): {}".format(str(e)))

def getStepData(ownerId, accessToken):
    """
    Pull step rate data from Fitbit
    First, we need to check the database to see the last time that we
    recorded a measurement. So then we can get the latest values from that 
    time until the current time. 
    Arguments: The caregivee's Fitbit ID and access token
    """

    # URL Format:
    # Intraday: https://api.fitbit.com/1/user/-/activities/steps/date/2018-11-05/1d/1min/time/00:00/00:01.json

    # Grab the latest date's steps for the caregivee/owner ID.
    lastRecord = steps.query.filter(steps.caregiveeID == ownerId).order_by(
        steps.date.desc()).first()
    
    
    # Also grab caregivee from caregivee table
    cgvee = caregivee.query.get(ownerId)

    # Format: 2022-10-21
    today = datetime.now(timezone("US/Eastern")).date()
    currentTime = datetime.now(timezone("US/Eastern")).time()
    currentTime = time(
        currentTime.hour, currentTime.minute, currentTime.second)

    # If there is not an entry for today, setup variables for fitbit api call to get todays values.
    if lastRecord == None or lastRecord.date != today:
        startTime = str(datetime.min.time())
        prevTotalSteps = 0

    # If the record exists for today, .
    else:
        # Get last time recorded minus 1 minute and previous steps to last recorded steps.
        # t2 = datetime.combine(date.min, lastRecord.timeMeasured) - datetime.min
        startTime = str(lastRecord.hourlyTime + timedelta(minutes=.1))
        prevTotalSteps = lastRecord.currentDayTotal

    # endTime will look like: 13:59:55
    endTime = datetime.now(timezone("US/Eastern"))
    deltaEndTime = endTime
    endTime = str(endTime.strftime("%H:%M:%S"))

    authHeader = "Bearer " + accessToken
    requestHeaders = {
        "Content-Type": "application/x-www-form-urlencoded", "Authorization": authHeader}
    urlBase = "https://api.fitbit.com/1/user/"
    url = urlBase + ownerId + "/activities/steps/date/" + str(today) + \
        "/1d/1min/time/" + startTime + "/" + endTime + ".json"

    print("URL: " + url)

    responseFromFitbit = requests.get(url, headers=requestHeaders)

    print("STEP RESPONSE FROM FITBIT: " + responseFromFitbit.text)

    try:
        responseFromFitbit = responseFromFitbit.json()

        totals = responseFromFitbit.get("activities-steps")
        values = responseFromFitbit.get("activities-steps-intraday")

        # The JSON packet we get is a list of dicts, but we only need the values,
        # not the keys. We also have two different lists to parse. We need the
        # day's total steps from one list, and the values from the other.
        # Here's an example response:
        #
        #  "activities-steps":[
        #    {"dateTime":"2014-09-05","value":1433}
        #    ],
        #    "activities-steps-intraday":{
        #        "dataset":[
        #            {"time":"00:05:00","value":287},
        #            {"time":"00:06:00","value":287},
        #            {"time":"00:07:00","value":287},
        #            {"time":"00:08:00","value":287},
        #            {"time":"00:09:00","value":287},
        #        ],
        #        "datasetInterval":1,
        #        "datasetType": "minute"
        #    }

        # total steps for today. 0 for no entry on todays date, else added onto steps from today.
        totalList = [d["value"] for d in totals]
        total = int(totalList[-1]) + prevTotalSteps
        print("total: {}".format(total))
        print(f"total - previous steps: {total - prevTotalSteps}")
        print(f"total[-1]: {totalList[-1]}")

        times = [d["time"] for d in values.get("dataset")]
        values = [d["value"] for d in values.get("dataset")]
    except Exception as e:
        print("Error. Check access privileges or check if last update was within 1 minute.")
        return jsonify({"error": str(e)}), 400
    
        
    # yesterday = today - timedelta(days=1)
    currentTime = datetime.now(timezone("US/Eastern")).time()
    currentDateTime = datetime.combine(today, currentTime)
    currentTimeMinus60Mins = (currentDateTime - timedelta(minutes=60)).time()

    # print("currentTime: {} currentDateTime: {} currentTimeMinus60Mins: {}".format(currentTime, currentDateTime, currentTimeMinus60Mins))
    
    lastTime = (datetime.min  + timedelta(minutes=1)).time()
    lastDateTime = datetime.combine(today, lastTime)
    totalHourlySteps = 0
    timeNoSteps = 0
    intervalDiffTime = 0
    
    if lastRecord != None and lastRecord.date == today and int(totalList[-1]) > 0:
        lastRecord.noStepTime = deltaEndTime
    
    # If record is for today, update total and time measured.
    if lastRecord != None and lastRecord.date == today:
        lastTime = (datetime.min + lastRecord.timeMeasured).time()
        lastDateTime = datetime.combine(lastRecord.date, lastTime)


        timeDiff2 = (deltaEndTime).time()
        timeDiff2 = datetime.combine(date.min, timeDiff2) - datetime.min
        timeDiff1 = (datetime.min + lastRecord.timeMeasured).time()
        timeDiff1 = datetime.combine(date.min, timeDiff1) - datetime.min
        print("TimeDiff2 = {} TimeDiff1 = {}".format(timeDiff2, timeDiff1))

        difference = (timeDiff2 - timeDiff1).total_seconds() / 3600
        print(f"Difference {difference}")


        diffTime1 = (lastRecord.noStepTime).time()
        diffTime1 = datetime.combine(date.min, diffTime1) - datetime.min
        print("TimeDiff2 = {} diffTime1 = {}".format(timeDiff2, diffTime1))

        timeNoSteps = (timeDiff2 - diffTime1).total_seconds() / 3600
        print(f"timeNoSteps {timeNoSteps}")


        intervalDiff= (lastRecord.intervalTime).time()
        intervalDiff= datetime.combine(date.min, intervalDiff) - datetime.min
        print("TimeDiff2 = {} intervalDiff = {}".format(timeDiff2, intervalDiff))

        intervalDiffTime = (timeDiff2 - intervalDiff).total_seconds() / 3600
        print(f"intervalDiffTime {intervalDiffTime}")


        if difference <= 1:
            lastRecord.hourlyTotal += int(totalList[-1])
            totalHourlySteps += int(totalList[-1])
        else:
            lastRecord.timeMeasured = endTime
            lastRecord.hourlyTotal = int(totalList[0])
            totalHourlySteps = lastRecord.hourlyTotal

        lastRecord.hourlyTime = endTime

        # print("lastTime: {} lastDateTime: {} datetime.min: {}".format(lastTime, lastDateTime, datetime.min))
        if lastRecord.currentDayTotal != total:
            lastRecord.currentDayTotal += total - prevTotalSteps
        
        print(lastRecord.toJSON())

        db.session.commit()

    # If entry doesnt exist at all or there is just not an entry for today, insert
    else:
        minTime = datetime.min
        lastRecord = steps(None, ownerId, today, int(totalList[0]), endTime, 0, endTime, deltaEndTime, minTime)
        
        db.session.add(lastRecord)
        db.session.commit()

    # Get the thresholds and the last record in the database
    # th = thresholds.query.get(ownerId)
    for row in connections.query.filter(connections.caregiveeID == ownerId).all():

        # Get caregiver id
        grabUser = caregiver.query.filter(caregiver.caregiverID == row.caregiverID).first()
        caregiverId = grabUser.caregiverID

        timeDiffSeconds = int((currentDateTime - lastDateTime).total_seconds())
        timeDiffHours = int(timeDiffSeconds/3600)

        # Make sure the caregivee isn't sleeping or in do not disturb mode, and
        # that the caregiver hasn't turned off alerts for this metric. No need
        # to send this notifications if so
        if row.timeWithoutStepsThreshold != None:
            if cgvee.doNotDisturb != 1 and cgvee.sleep != 1 and cgvee.recordSteps == 1:
                if timeNoSteps > (row.timeWithoutStepsThreshold) and intervalDiffTime >= 1:
                    lastRecord.intervalTime = deltaEndTime
                    db.session.commit()
                    try:
                        sendPushNotification(ownerId, "Time Without Steps", " has gone more than " + str(
                        int (timeNoSteps)) + " hour(s) without steps", "noStepsAlert", caregiverId)
                    except Exception as e:
                        print("Push notification error STEPS (time without steps threshold): {}".format(str(e)))
                        break

        if row.stepThreshold != None:
            if totalHourlySteps > row.stepThreshold:
                try:
                    sendPushNotification(ownerId, "Too Many Steps", " has taken more than " + str(
                    totalHourlySteps) + " steps in the past hour", "tooManyStepsAlert", caregiverId)
                except Exception as e:
                    print("Push notification error STEPS (hourly steps): {}".format(str(e)))


def getDeviceData(ownerId, accessToken):
    """
    Pull device rate data from Fitbit
    We'll only have one entry in this table for each caregivee. If there's
    no entry, we'll create one. Otherwise, we'll just update the data
    that's present. We don't really see the need for historical data here.
    Arguments: The caregivee's Fitbit ID and access token
    """

    # URL Format: https://api.fitbit.com/1/user/-/devices.json

    authHeader = "Bearer " + accessToken
    requestHeaders = {
        "Content-Type": "application/x-www-form-urlencoded", "Authorization": authHeader}
    urlBase = "https://api.fitbit.com/1/user/"
    url = urlBase + ownerId + "/devices.json"

    print("URL: " + url)

    responseFromFitbit = requests.get(url, headers=requestHeaders)

    print("DEVICE RESPONSE FROM FITBIT: " + responseFromFitbit.text)

    # Example response:
    #
    # [
    #   {
    #     "battery": "High",
    #     "batteryLevel": 100,
    #     "deviceVersion": "Alta HR",
    #     "features": [],
    #     "id": "678259720",
    #     "lastSyncTime": "2019-04-15T12:46:20.211",
    #     "mac": "CC01F5C24ED4",
    #     "type": "TRACKER"
    #   }
    # ]

    responseFromFitbit = responseFromFitbit.json()

    # See if there is an entry in the table for the caregivee
    device = fitbit.query.get(responseFromFitbit[0]["id"])

    if device == None:
        minTime = datetime.min
        device = fitbit(responseFromFitbit[0]["id"], ownerId, responseFromFitbit[0]["deviceVersion"],
                        responseFromFitbit[0]["battery"], responseFromFitbit[0]["type"],
                        responseFromFitbit[0]["lastSyncTime"], None, minTime)

        db.session.add(device)
        db.session.commit()
    else:
        device.battery = responseFromFitbit[0]["battery"]
        device.lastSyncTime = responseFromFitbit[0]["lastSyncTime"]

        db.session.commit()

    device = fitbit.query.get(responseFromFitbit[0]["id"])
    cgvee = caregivee.query.get(ownerId)

    # get an interval time of 1 hour from low/empty alert to low/empty alert
    currentTime = datetime.now(timezone("US/Eastern"))
    today = currentTime.date()
    intervalDate = (device.intervalTime).date()
    timeDiff2 = (currentTime).time()
    timeDiff2 = datetime.combine(date.min, timeDiff2) - datetime.min
    timeDiff1 = (device.intervalTime).time()
    timeDiff1 = datetime.combine(date.min, timeDiff1) - datetime.min
    print("TimeDiff2 = {} TimeDiff1 = {}".format(timeDiff2, timeDiff1))

    difference = (timeDiff2 - timeDiff1).total_seconds() / 3600
    print(f"Difference {difference}")

    # Send low or empty alert witn an hour of interval
    try:
        if ((responseFromFitbit[0]["battery"] == "Low" or responseFromFitbit[0]["battery"] == "Empty") and (difference >= 1 or today != intervalDate)):
            device.intervalTime = currentTime
            db.session.commit()
            sendPushNotificationAll(device.caregiveeID, "Fitbit Battery " +
                             responseFromFitbit[0]["battery"], "'s Fitbit has " + responseFromFitbit[0]["battery"].lower() + " charge", "batteryAlert")

    except Exception as e:
        return jsonify({"error": str(e)}), 400

    # Make sure the caregivee isn't sleeping or in do not disturb mode, and
    # that the caregiver hasn't turned off alerts for this metric. No need
    # to send this notifications if so
    # if cgvee.doNotDisturb != 1 and cgvee.sleep != 1 and cgvee.recordDeviceData == 1:
    #     # Check to send no sync alerts
    #     threeHoursAgo = datetime.now(timezone("US/Eastern")).replace(tzinfo=None) - timedelta(hours=3)
    #     timeDiffSeconds = (threeHoursAgo - device.lastSyncTime).total_seconds()

    #     if timeDiffSeconds > 10800.0:
    #         sendPushNotification(device.caregiveeID, "Fitbit Hasn't Synced", "'s Fitbit hasn't synced in over 3 hours", "noSyncAlert")
    #         device.lastSyncTime = datetime.now


def processSubscriptionsNotifications(incoming):
    """
    Once we receive a Fitbit Subscriptions notification, we'll setup a thread
    in the respondToSubscriptionsNotifications() method to call this method, 
    and then we'll return the required 204 to Fitbit. 
    """
    # Acquiring lock on this function for this thread
    # subscriptionLock.acquire()

    if incoming is None:
        subscriptionLock.release()
        return jsonify({"error": "Bad response from fitbit."}), 400
    print(incoming)

    caregivees = []
    rates = []

    # Get the ownerIds (the Fitibit IDs, which are also the caregiveeIDs)
    # from the incoming packet, then query the database for each one and append
    # those objects to a list
    for item in incoming:
        caregivees.append(caregivee.query.get(item.get("ownerId")))

    for cgvee in caregivees:
        if cgvee == None:
            continue
        # First, we need to check if we have to refresh the access token
        if UTC.localize(cgvee.accessTokenExpiresOn) <= datetime.now(timezone("US/Eastern")):
            responseFromFitbit = refreshAccessToken(cgvee)
            cgvee.fitbitAccessToken = responseFromFitbit.get("access_token")
            cgvee.fitbitRefreshToken = responseFromFitbit.get("refresh_token")
            cgvee.accessTokenExpiresOn = datetime.now(timezone(
                "US/Eastern")) + timedelta(seconds=responseFromFitbit.get("expires_in"))

            db.session.commit()

        print("Processing data for caregivee " + cgvee.caregiveeID)

        # # Make sure the caregivee is allowing us to monitor their data
        # if cgvee.monitoring == 1:
        #     # Get heart rate data
        #     if cgvee.recordHR == 1:
        #         getHeartRateData(cgvee.caregiveeID, cgvee.fitbitAccessToken)

        #     # Get step data
        #     if cgvee.recordSteps == 1:
        #         getStepData(cgvee.caregiveeID, cgvee.fitbitAccessToken)

        #     # Get device data
        #     if cgvee.recordDeviceData == 1:
        #         getDeviceData(cgvee.caregiveeID, cgvee.fitbitAccessToken)

        # Make sure the caregivee is allowing us to monitor their data
        if cgvee.monitoring == 1:
            getDeviceData(cgvee.caregiveeID, cgvee.fitbitAccessToken)
            getHeartRateData(cgvee.caregiveeID, cgvee.fitbitAccessToken)
            getStepData(cgvee.caregiveeID, cgvee.fitbitAccessToken)
    # subscriptionLock.release()

# send push notification to a single caregiver
def sendPushNotification (caregiveeId, title, body, alertType, caregiverId):
    """
    Send push notification to users devices.
    Arguments: caregiveeId = caregivee's Fitbit ID, title = message title, body = message body
    """

    # Also get the caregivee's name
    cgvee = caregivee.query.get(caregiveeId)
    cgveeUser = users.query.get(cgvee.userID)

    #  get caregiver
    cgvr = caregiver.query.get(caregiverId)
    cgvrUser = users.query.get(cgvr.userID)

    print("Sending Notification With Message: " + body)

    now = datetime.now(timezone("US/Eastern"))
    message = cgveeUser.firstName + " " + cgveeUser.lastName + body

    newAlert = alerts(None, caregiveeId, now, title,
                      message, alertType, 1, caregiverId)
    db.session.add(newAlert)
    db.session.commit()

    # get token
    token = cgvrUser.messageToken
    print("Notification sending to caregiver " + cgvrUser.firstName +
      " " + cgvrUser.lastName + " " + str(cgvrUser.userID))

    try:
        response = PushClient().publish(
            PushMessage(to=token,
                        title=title,
                        body=message,
                        data=None))
    except PushServerError as exc:
        # Encountered some likely formatting/validation error.
        rollbar.report_exc_info(
            extra_data={
                'token': token,
                'message': message,
                'title': title,
                'extra': None,
                'errors': exc.errors,
                'response_data': exc.response_data,
            })
        raise
    except (ConnectionError, HTTPError) as exc:
        # Encountered some Connection or HTTP error - retry a few times in
        # case it is transient.
        rollbar.report_exc_info(
            extra_data={'token': token,'title': title, 'message': message, 'extra': None})
        raise self.retry(exc=exc)

    try:
        # We got a response back, but we don't know whether it's an error yet.
        # This call raises errors so we can handle them with normal exception
        # flows.
        response.validate_response()
    except DeviceNotRegisteredError:
        # Mark the push token as inactive
        from notifications.models import PushToken
        PushToken.objects.filter(token=token).update(active=False)
    except PushTicketError as exc:
        # Encountered some other per-notification error.
        rollbar.report_exc_info(
            extra_data={
                'token': token,
                'title': title,
                'message': message,
                'extra': None,
                'push_response': exc.push_response._asdict(),
            })
        raise self.retry(exc=exc)

# Send push notification to all caregivers
def sendPushNotificationAll (caregiveeId, title, body, alertType):
    """
    Send push notification to users devices.
    Arguments: caregiveeId = caregivee's Fitbit ID, title = message title, body = message body
    """

    # Also get the caregivee's name
    cgvee = caregivee.query.get(caregiveeId)
    cgveeUser = users.query.get(cgvee.userID)

    print("Sending Notification With Message: " + body)

    now = datetime.now(timezone("US/Eastern"))
    message = cgveeUser.firstName + " " + cgveeUser.lastName + body


    for row in connections.query.filter(connections.caregiveeID == caregiveeId).all():

        # Need to search caregiver table for caregivee ID, get userId and then use userId to
        # get messageToken from user table
        grabUser = caregiver.query.filter(caregiver.caregiverID == row.caregiverID).first()
        caregiverId = grabUser.caregiverID
        user = users.query.filter(users.userID == grabUser.userID).first()

        newAlert = alerts(None, caregiveeId, now, title,
                      message, alertType, 1, caregiverId)
        db.session.add(newAlert)
        db.session.commit()
        # get token
        token = user.messageToken
        print("Notification sending to caregiver " + user.firstName +
          " " + user.lastName + " " + str(user.userID))

        try:
            response = PushClient().publish(
                PushMessage(to=token,
                            title=title,
                            body=message,
                            data=None))
        except PushServerError as exc:
            # Encountered some likely formatting/validation error.
            rollbar.report_exc_info(
                extra_data={
                    'token': token,
                    'message': message,
                    'title': title,
                    'extra': None,
                    'errors': exc.errors,
                    'response_data': exc.response_data,
                })
            raise
        except (ConnectionError, HTTPError) as exc:
            # Encountered some Connection or HTTP error - retry a few times in
            # case it is transient.
            rollbar.report_exc_info(
                extra_data={'token': token,'title': title, 'message': message, 'extra': None})
            raise self.retry(exc=exc)

        try:
            # We got a response back, but we don't know whether it's an error yet.
            # This call raises errors so we can handle them with normal exception
            # flows.
            response.validate_response()
        except DeviceNotRegisteredError:
            # Mark the push token as inactive
            from notifications.models import PushToken
            PushToken.objects.filter(token=token).update(active=False)
        except PushTicketError as exc:
            # Encountered some other per-notification error.
            rollbar.report_exc_info(
                extra_data={
                    'token': token,
                    'title': title,
                    'message': message,
                    'extra': None,
                    'push_response': exc.push_response._asdict(),
                })
            raise self.retry(exc=exc)


def sendRequestNotification (recipientUserID, sendingUserID):
    """
    Send Request notification to users devices for Request recieved.
    Arguments: recipientUserID = receiving user's ID, sendingUserID = sending user's id
    """

    receivingUser = users.query.get(recipientUserID)
    sendingUser = users.query.get(sendingUserID)
    print("Notification sending to user " + receivingUser.firstName +
          " " + receivingUser.lastName + " " + str(receivingUser.userID))


    token = receivingUser.messageToken
    cgvee = caregivee.query.filter(caregivee.userID == recipientUserID).first()

    # send the notification only if it is a caregiver or if the caregivee is not on sleep mode or do not disturb
    if cgvee is None:

        title = "Caregivee Request"
        message = sendingUser.firstName + " " + sendingUser.lastName + " " + "wants to be your caregivee"

        try:
            response = PushClient().publish(
                PushMessage(to=token,
                            title=title,
                            body=message,
                            data=None))
        except PushServerError as exc:
            # Encountered some likely formatting/validation error.
            rollbar.report_exc_info(
                extra_data={
                    'token': token,
                    'message': message,
                    'title': title,
                    'extra': None,
                    'errors': exc.errors,
                    'response_data': exc.response_data,
                })
            raise
        except (ConnectionError, HTTPError) as exc:
            # Encountered some Connection or HTTP error - retry a few times in
            # case it is transient.
            rollbar.report_exc_info(
                extra_data={'token': token,'title': title, 'message': message, 'extra': None})
            raise self.retry(exc=exc)

        try:
            # We got a response back, but we don't know whether it's an error yet.
            # This call raises errors so we can handle them with normal exception
            # flows.
            response.validate_response()
        except DeviceNotRegisteredError:
            # Mark the push token as inactive
            from notifications.models import PushToken
            PushToken.objects.filter(token=token).update(active=False)
        except PushTicketError as exc:
            # Encountered some other per-notification error.
            rollbar.report_exc_info(
                extra_data={
                    'token': token,
                    'title': title,
                    'message': message,
                    'extra': None,
                    'push_response': exc.push_response._asdict(),
                })
            raise self.retry(exc=exc)

    elif cgvee is not None and cgvee.doNotDisturb != 1 and cgvee.sleep != 1:

        title = "Caregiver Request"
        message = sendingUser.firstName + " " + sendingUser.lastName + " " + "wants to be your caregiver"

        try:
            response = PushClient().publish(
                PushMessage(to=token,
                            title=title,
                            body=message,
                            data=None))
        except PushServerError as exc:
            # Encountered some likely formatting/validation error.
            rollbar.report_exc_info(
                extra_data={
                    'token': token,
                    'message': message,
                    'title': title,
                    'extra': None,
                    'errors': exc.errors,
                    'response_data': exc.response_data,
                })
            raise
        except (ConnectionError, HTTPError) as exc:
            # Encountered some Connection or HTTP error - retry a few times in
            # case it is transient.
            rollbar.report_exc_info(
                extra_data={'token': token,'title': title, 'message': message, 'extra': None})
            raise self.retry(exc=exc)

        try:
            # We got a response back, but we don't know whether it's an error yet.
            # This call raises errors so we can handle them with normal exception
            # flows.
            response.validate_response()
        except DeviceNotRegisteredError:
            # Mark the push token as inactive
            from notifications.models import PushToken
            PushToken.objects.filter(token=token).update(active=False)
        except PushTicketError as exc:
            # Encountered some other per-notification error.
            rollbar.report_exc_info(
                extra_data={
                    'token': token,
                    'title': title,
                    'message': message,
                    'extra': None,
                    'push_response': exc.push_response._asdict(),
                })
            raise self.retry(exc=exc)


def sendChatNotification(recipientUserID, sendingUserID, message):
    # Setup a thread to send the notification in the background
    print('start chat notif thread')
    t = threading.Thread(target=sendChatNotificationInBackground(
        recipientUserID, sendingUserID, message))
    t.start()


def sendChatNotificationInBackground(recipientUserID, sendingUserID, message):
    """
    Send push notification to users devices for chat recieved.
    Arguments: recipientUserID = receiving user's ID, sendingUserID = sending user's id, message = message body
    """

    receivingUser = users.query.get(recipientUserID)
    sendingUser = users.query.get(sendingUserID)
    print("Notification sending to user " + receivingUser.firstName +
          " " + receivingUser.lastName + " " + str(receivingUser.userID))

    push_service = FCMNotification(api_key=firebaseApiKey)

    reg_id = receivingUser.messageToken
    message_title = "Carebit Message"
    message_body = sendingUser.firstName + " " + \
        sendingUser.lastName + ": " + message
    cgvee = caregivee.query.filter(caregivee.userID == recipientUserID).first()

    # send the notification only if it is a caregiver or if the caregivee is not on sleep mode or do not disturb
    if cgvee is None:
        try:
            result = push_service.notify_single_device(
                registration_id=reg_id, message_title=message_title, message_body=message_body, sound="alert-sound.aif")
            print(result)
        except:
            print('failed to send chat notification')
    elif cgvee is not None and cgvee.doNotDisturb != 1 and cgvee.sleep != 1:
        try:
            result = push_service.notify_single_device(
                registration_id=reg_id, message_title=message_title, message_body=message_body, sound="alert-sound.aif")
            print(result)
        except:
            print('failed to send chat notification')


def createCaregivee(code, userID):# physName physEmail, physNum):
    """
    Helper method to create caregivees
    The app will do the OAuth with Fitbit, and then send us the JSON packet 
    that it receives. That packet looks like this:
    {
        "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0MzAzNDM3MzUsInNjb3BlcyI6Indwcm8gd2xvYyB3bnV0IHdzbGUgd3NldCB3aHIgd3dlaSB3YWN0IHdzb2MiLCJzdWIiOiJBQkNERUYiLCJhdWQiOiJJSktMTU4iLCJpc3MiOiJGaXRiaXQiLCJ0eXAiOiJhY2Nlc3NfdG9rZW4iLCJpYXQiOjE0MzAzNDAxMzV9.z0VHrIEzjsBnjiNMBey6wtu26yHTnSWz_qlqoEpUlpc",
        "expires_in": 3600,
        "refresh_token": "c643a63c072f0f05478e9d18b991db80ef6061e4f8e6c822d83fed53e5fafdd7",
        "token_type": "Bearer",
        "user_id": "26FWFL"
    }
    and we'll either create the caregivee if they don't exist, or update their
    tokens if they do.
    Return caregiveeID
    """

    # Grab the authorization code, and request tokens
    responseFromFitbit = requestAccessAndRefreshTokens(code, "app")
    print("Response from fitbit in createCaregivee: ")
    print(responseFromFitbit)
    if (responseFromFitbit == None):
        return 0
    # See if the caregivee exists
    
    newCaregivee = caregivee.query.get(responseFromFitbit.get("user_id"))

    if newCaregivee == None:
        user = responseFromFitbit.get("user_id")
        accessToken = responseFromFitbit.get("access_token")
        refreshToken = responseFromFitbit.get("refresh_token")
        expiresOn = datetime.now(timezone(
            "US/Eastern")) + timedelta(seconds=responseFromFitbit.get("expires_in"))
        print("Creating new caregivee for ID: " + user)
        newCaregivee = caregivee(
            user, accessToken, expiresOn, refreshToken, None, userID)# physName, physEmail, physNum)

        print("NEW CAREGIVEE TOKEN ASSIGNMENT:")
        print("ACCESS TOKEN: " + newCaregivee.fitbitAccessToken)
        print("REFRESH TOKEN: " + newCaregivee.fitbitRefreshToken)
        print("EXPIRES ON: " + str(newCaregivee.accessTokenExpiresOn))

        db.session.add(newCaregivee)
        db.session.commit()

        # Get the new caregivee
        newCaregivee = caregivee.query.get(user)

        # Create the threshold table entry
        # highAndLowRates = thresholds(
        #     newCaregivee.caregiveeID, None, None, None)
        # db.session.add(highAndLowRates)
        # db.session.commit()

        subID = str(newCaregivee.caregiveeID)

        # Create the subscription
        authHeader = "Bearer " + newCaregivee.fitbitAccessToken
        header = {"Authorization": authHeader, "content-length": "0"}
        url = "https://api.fitbit.com/1/user/-/activities/apiSubscriptions/" + subID + ".json"
        print("header:", header)
        print("url:", url)
        responseFromFitbit = requests.post(url, headers=header)

        print("Subscription API replied: " + str(responseFromFitbit))
        print("Reason: " + str(responseFromFitbit.reason))
        print("Response body: " + str(responseFromFitbit.content))
        print("with status: " + str(responseFromFitbit.status_code))
        print("Verify: ", subsVerify)

        return newCaregivee.caregiveeID
    # Caregivee has been created before but there was a problem so its not a valid caregivee yet.
    elif newCaregivee != None and newCaregivee.userID == None:
        print("2nd case for create caregivee")
        return 1
    else:
        newCaregivee.fitbitAccessToken = responseFromFitbit.get("access_token")
        newCaregivee.fitbitRefreshToken = responseFromFitbit.get(
            "refresh_token")
        newCaregivee.accessTokenExpiresOn = datetime.now(timezone(
            "US/Eastern")) + timedelta(seconds=responseFromFitbit.get("expires_in"))

        print("EXITSTING CAREGIVEE TOKEN ASSIGNMENT:")
        print("ACCESS TOKEN: " + newCaregivee.fitbitAccessToken)
        print("REFRESH TOKEN: " + newCaregivee.fitbitRefreshToken)
        print("EXPIRES ON: " + str(newCaregivee.accessTokenExpiresOn))

        db.session.commit()

        # Create the subscription if one doesn't already exist
        subID = str(newCaregivee.caregiveeID)

        # Create the subscription
        authHeader = "Bearer " + newCaregivee.fitbitAccessToken
        header = {"Authorization": authHeader, "content-length": "0"}
        url = "https://api.fitbit.com/1/user/-/activities/apiSubscriptions/" + subID + ".json"
        print("header:", header)
        print("url:", url)
        responseFromFitbit = requests.post(url, headers=header)

        print("Subscription API replied: " + str(responseFromFitbit))
        print("Reason: " + str(responseFromFitbit.reason))
        print("Response body: " + str(responseFromFitbit.content))
        print("with status: " + str(responseFromFitbit.status_code))
        print("Verify: ", subsVerify)

        return newCaregivee.caregiveeID


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    """
    Helper for our logout function. This checks the JWT revocation store to see
    if a token has been blacklisted
    """
    jti = jwt_payload['jti']
    entry = revokedStore.get(jti)
    if entry is None:
        return True
    return entry == 'true'


###############################################################################
#                     API Endpoints for Fitbit Interaction                    #
###############################################################################


@app.route('/profile', methods=["GET"], defaults={"code": None})
def profile(code):
    """
    This is a temporary endpoint for doing oauth logins via the web interface.
    Just for testing.
    If someone simply calls this url, we'll take them to the profile page.
    But if we're trying to authenticate with Fitbit, they will send a url parameter
    back to this endpoint, which we'll use to get the user's access and refresh
    tokens. So we need to catch that if it is present.
    """
    code = rq.args.get('code')

    if code != None:
        responseFromFitbit = requestAccessAndRefreshTokens(code, "web")

        # Check to see if the user exists. If not, create them. Otherwise,
        # just add the access and refresh tokens
        if responseFromFitbit != None:

            print("REQUEST ACCESS AND REFRESH TOKENS RESPONSE:")
            print("USER ID: " + responseFromFitbit.get("user_id"))
            print("ACCESS TOKEN: " + responseFromFitbit.get("access_token"))
            print("REFRESH TOKEN: " + responseFromFitbit.get("refresh_token"))
            print("EXPIRES ON: " + str(datetime.now(timezone("US/Eastern")
                                                    ) + timedelta(seconds=responseFromFitbit.get("expires_in"))))

            newCaregivee = caregivee.query.get(
                responseFromFitbit.get("user_id"))

            if newCaregivee == None:
                user = responseFromFitbit.get("user_id")
                accessToken = responseFromFitbit.get("access_token")
                refreshToken = responseFromFitbit.get("refresh_token")
                expiresOn = datetime.now(timezone(
                    "US/Eastern")) + timedelta(seconds=responseFromFitbit.get("expires_in"))

                newCaregivee = caregivee(
                    user, accessToken, expiresOn, refreshToken, None, None)

                print("NEW CAREGIVEE TOKEN ASSIGNMENT:")
                print("ACCESS TOKEN: " + newCaregivee.fitbitAccessToken)
                print("REFRESH TOKEN: " + newCaregivee.fitbitRefreshToken)
                print("EXPIRES ON: " + str(newCaregivee.accessTokenExpiresOn))

                highAndLowRates = thresholds(user, None, None, None)
                db.session.add(highAndLowRates)
                db.session.add(newCaregivee)
                db.session.commit()

                # Create the subscription
                newCaregivee = caregivee.query.get(user)

                authHeader = "Bearer " + newCaregivee.fitbitAccessToken
                header = {"Authorization": authHeader}
                urlBase = "https://api.fitbit.com/1/user/"
                url = urlBase + newCaregivee.caregiveeID + "/activities/apiSubscriptions/" + \
                    str(newCaregivee.subscriptionID) + ".json"

                responseFromFitbit = requests.post(url, headers=header)

                print("Subscription API replied: " + str(responseFromFitbit))
                print("with status: " + str(responseFromFitbit.status_code))
            else:
                newCaregivee.fitbitAccessToken = responseFromFitbit.get(
                    "access_token")
                newCaregivee.fitbitRefreshToken = responseFromFitbit.get(
                    "refresh_token")
                newCaregivee.accessTokenExpiresOn = datetime.now(timezone(
                    "US/Eastern")) + timedelta(seconds=responseFromFitbit.get("expires_in"))

                print("EXITSTING CAREGIVEE TOKEN ASSIGNMENT:")
                print("ACCESS TOKEN: " + newCaregivee.fitbitAccessToken)
                print("REFRESH TOKEN: " + newCaregivee.fitbitRefreshToken)
                print("EXPIRES ON: " + str(newCaregivee.accessTokenExpiresOn))

                db.session.commit()

    return app.send_static_file('profile.html')


# Fitbit Subscriptions API endpoint
@app.route('/fitbit-notifications', methods=["GET", "POST"])
def respondToSubscriptionsNotifications():
    """
    If we receive a GET request to this endpoint, Fitbit is trying to verify
    our appliction. 
    If we receive a POST request, Fitbit is notifying our application of 
    available data for us to request. 
    """
    if rq.method == "GET":
        print("Fitbit API trying to verify Carebit")

        verify = rq.args.get('verify')

        if verify == subsVerify:
            return "", 204
        else:
            return "", 404
    else:
        print("Fitbit API has new data for Carebit")

        # Get the incoming Subscriptions notification
        incoming = rq.get_json()
        print("Incoming fitbit data: {}".format(incoming))

        # Setup a thread to process the info so we can return a response right
        # away to Fitbit and process the data in the background
        
        t = threading.Thread(
            target=processSubscriptionsNotifications(incoming))
        # t.daemon = True
        t.start()
        # t.join()
        
        return "", 204


###############################################################################
#                    API Endpoints for Carebit Interaction                    #
###############################################################################


@app.route('/login', methods=["POST"])
def login():
    """
    Login to carebit account, basic email and password verification.
    Example body JSON:
    {
        "email": "email@email.com',
        "password": "pass"
    }
    """

    # Parse json request
    req_data = rq.get_json()

    email = req_data["email"]
    password = req_data["password"]

    # Find user with correlating email
    currentUser = users.query.filter(users.email == email).first()

    # If the user existed verify password
    if (currentUser == None):
        print("Email Not found")
        return jsonify({'message': "Email not found"}), 401
    else:

        # Check for caregiver or caregivee to return proper values and JWT tokens
        if (bcrypt.check_password_hash(currentUser.password, password)):
            currentCaregiver = caregiver.query.filter(
                caregiver.userID == currentUser.userID).first()
            currentCaregivee = caregivee.query.filter(
                caregivee.userID == currentUser.userID).first()

            # Create the JWT
            accessToken = create_access_token(
                identity=currentUser.userID, expires_delta=timedelta(days=31))
            refreshToken = create_refresh_token(identity=currentUser.userID)

            ret = {
                'access_token': accessToken,
                'refresh_token': refreshToken,
                'userID': currentUser.userID,
                'firstName': currentUser.firstName,
                'lastName': currentUser.lastName,
                'caregiveeID': None,
                'caregiverID': None,
                'type': None,
                'phone': currentUser.phone,
                'email': currentUser.email,
                'authPhase': currentUser.authPhase
            }

            # Store the JWT in redis with a status of not currently revoked. We
            # can use the `get_jti()` method to get the unique identifier string for
            # each token. We can also set an expires time on these tokens in redis,
            # so they will get automatically removed after they expire. We will set
            # everything to be automatically removed shortly after the token expires
            accessJTI = get_jti(encoded_token=accessToken)
            refreshJTI = get_jti(encoded_token=refreshToken)
            revokedStore.set(accessJTI, 'false', ACCESS_EXPIRES * 1.2)
            revokedStore.set(refreshJTI, 'false', REFRESH_EXPIRES * 1.2)

            # Check if user is caregiver or caregivee
            if currentCaregiver != None:
                ret["caregiverID"] = currentCaregiver.caregiverID
                ret["type"] = "caregiver"

                allCaregivees = []

                # get all caregivees
                for row in connections.query.filter(connections.caregiverID == currentCaregiver.caregiverID).all():
                    dictRet = dict(row.__dict__)
                    if dictRet["status"] == "accepted":
                        dictRet.pop('_sa_instance_state', None)

                    
                        grabUser = caregivee.query.filter(caregivee.caregiveeID == dictRet["caregiveeID"]).first()
                        user = users.query.filter(users.userID == grabUser.userID).first()

                        dictRet.pop('caregiverID', None)
                        dictRet.pop('healthProfile', None)
                        
                        dictRet["firstName"] = user.firstName
                        dictRet["lastName"] = user.lastName
                        dictRet["email"] = user.email
                        dictRet["phone"] = user.phone
                        dictRet["physName"] = grabUser.physName
                        dictRet["physPhone"] = grabUser.physPhone
                        # dictRet["healthProfile"] = row.healthProfile
                        dictRet["lowHRThreshold"] = row.lowHRThreshold
                        dictRet["highHRThreshold"] = row.highHRThreshold
                        dictRet["currentDayLowHR"] = row.currentDayLowHR
                        dictRet["currentDayHighHR"] = row.currentDayHighHR
                        dictRet["stepThreshold"] = row.stepThreshold
                        dictRet["timeWithoutHRThreshold"] = row.timeWithoutHRThreshold
                        dictRet["timeWithoutStepsThreshold"] = row.timeWithoutStepsThreshold
                        
                        allCaregivees.append(dictRet)

                ret["caregiveeID"] = allCaregivees

                # Get their caregivee's ID
                # if currentCaregiver.caregiveeID != None:
                #     ret["caregiveeID"] = currentCaregiver.caregiveeID

            elif currentCaregivee != None:
                ret["caregiveeID"] = currentCaregivee.caregiveeID
                ret["type"] = "caregivee"
                ret["physName"] = currentCaregivee.physName
                ret["physPhone"] = currentCaregivee.physPhone
                ret["healthProfile"] = currentCaregivee.healthProfile

                allCaregivers = []

                # Get all their caregiver's ID
                for row in connections.query.filter(connections.caregiveeID == currentCaregivee.caregiveeID).all():
                    dictRet = dict(row.__dict__)
                    if dictRet["status"] == "accepted":
                        dictRet.pop('_sa_instance_state', None)
                        dictRet.pop('caregiveeID', None)

                        grabUser = caregiver.query.filter(caregiver.caregiverID == dictRet["caregiverID"]).first()
                        user = users.query.filter(users.userID == grabUser.userID).first()

                        dictRet["phone"] = user.phone
                        dictRet["firstName"] = user.firstName
                        dictRet["lastName"] = user.lastName
                        dictRet["email"] = user.email
                        # dictRet["healthProfile"] = row.healthProfile
                        dictRet["lowHRThreshold"] = row.lowHRThreshold
                        dictRet["highHRThreshold"] = row.highHRThreshold
                        dictRet["currentDayLowHR"] = row.currentDayLowHR
                        dictRet["currentDayHighHR"] = row.currentDayHighHR
                        dictRet["stepThreshold"] = row.stepThreshold
                        dictRet["timeWithoutHRThreshold"] = row.timeWithoutHRThreshold
                        dictRet["timeWithoutStepsThreshold"] = row.timeWithoutStepsThreshold

                        allCaregivers.append(dictRet)
                
                ret["caregiverID"] = allCaregivers
                # cgvr = caregiver.query.filter(
                #     caregiver.caregiveeID == currentCaregivee.caregiveeID).first()
                # if cgvr != None and cgvr.caregiveeID != None:
                #     ret["caregiverID"] = cgvr.caregiverID

            print("Login Successful")
            print(ret)
            return jsonify(ret), 200
        else:
            print("Password Incorrect")
            return jsonify({'message': "Password incorrect"}), 401


@app.route('/logout/<int:userID>', methods=["DELETE"])
@jwt_required()
def logout(userID):
    """
    Here, we'll blacklist the user's JWT access token, and delete their 
    message token from the DB
    """

    currentUser = get_jwt_identity()
    user = users.query.get(userID)
    print("made it here")
    if user is None:
        return jsonify({"error": "User not found"}), 204

    # Remove message token
    user.messageToken = None
    db.session.commit()

    # Blacklist JWT access token
    jti = get_jwt()['jti']
    revokedStore.set(jti, 'true', ACCESS_EXPIRES * 1.2)

    print("Logging out user " + str(user.userID))

    return jsonify({"result": "Logout successful"}), 200


@app.route('/revokeRefreshToken', methods=["DELETE"])
@jwt_required(refresh=True)
def logout2():
    """
    We can't blacklist both the access and refresh tokens in the same call,
    since they share the same namespace. So this extra endpoint is to revoke
    the refresh token
    """
    jti = get_jwt()['jti']
    revokedStore.set(jti, 'true', REFRESH_EXPIRES * 1.2)

    print("Revoking refresh token")

    return jsonify({"result": "Logout successful"}), 200


@app.route('/user', methods=["POST"])
def createUser():

    """
    Create user, caregiver, or caregivee 
    Example expected JSON:
    Caregiver:
    {
        "type": "caregiver",
        "firstName": "Test",
        "lastName": "User",
        "phone": "1234567",
        "email": "email@email.email",
        "password": "password",
        "mobilePlatform": "ios",
        "caregiverID": 12
    }
    Caregivee:
    {
        "type": "caregivee",
        "firstName": "Test",
        "lastName": "User",
        "phone": "1234567",
        "email": "email@email.email",
        "password": "password",
        "mobilePlatform": "ios",
        "caregiverID": 12
    }
    """
    # Parse json request
    req_data = rq.get_json()

    try:
        userType = req_data["type"]
        firstName = req_data["firstName"]
        lastName = req_data["lastName"]
        phone = req_data["phone"]
        if len(phone) > 19:
            return jsonify({"error": "Phone length."}), 400
        email = req_data["email"]
        password = bcrypt.generate_password_hash(req_data["password"])
        mobilePlatform = req_data["mobilePlatform"]
        cgverID = req_data["caregiverID"]
    except KeyError :
        return jsonify({"error": "Check request body for required input."}), 400
        
    # Check for email and phone in database
    newUser = users.query.filter(users.email == email).first()
    newUserPhone = users.query.filter(users.phone == phone).first()

    # 0 default, 1 for email error message, 2 for phone error message
    errNum = 0
    if newUser:
        errNum = 1
    elif newUserPhone:
        errNum = 2

    if newUser is None and newUserPhone is None:
        try:
            v = validate_email(email)  # validate and get info
            email = v["email"]  # replace with normalized form
            print(email)
        except EmailNotValidError as e:
            print("Email is not valid, email received: " + email)
            print("Error: " + str(e))
            # Send back error
            return jsonify({"error": "Email is not valid"}), 400

        print("Create User")
        # Create the new user
        try:
            if userType == "caregiver":
                newUser = users(None, firstName, lastName, phone,
                        email, password, None, mobilePlatform, 1)

                db.session.add(newUser)
                db.session.commit()

            elif userType == "caregivee":
                newUser = users(None, firstName, lastName, phone,
                        email, password, None, mobilePlatform, 6)

                if cgverID != None:
                    theCgverCheck = caregiver.query.filter(caregiver.caregiverID == cgverID).first()
                    grabCgverUser = users.query.filter(users.userID == theCgverCheck.userID).first()
                    grabCgverUser.authPhase = 3
                    db.session.commit()

                db.session.add(newUser)
                db.session.commit()
            else:
                raise Exception
        except Exception as e:
            return jsonify({"error": str(e)}), 400

        # Get User to use for caregiver and caregivee
        newUser = users.query.filter(users.email == email).first()

        # Get userID to use for return values
        ret = {'userID': newUser.userID}

        # Create caregiver
        if userType == "caregiver":
            print("Creating Caregiver")
            newCaregiver = caregiver(None, newUser.userID)
            db.session.add(newCaregiver)
            db.session.commit()

            # Get caregiver to use for return values
            newCaregiver = caregiver.query.filter(
                caregiver.userID == newUser.userID).first()
            ret['caregiverID'] = newCaregiver.caregiverID

        # Create and return JWT access and refresh tokens
        access_token = create_access_token(
            identity=newUser.userID, expires_delta=timedelta(days=31))
        refresh_token = create_refresh_token(newUser.userID)

        # Store the JWT in redis with a status of not currently revoked. We
        # can use the `get_jti()` method to get the unique identifier string for
        # each token. We can also set an expires time on these tokens in redis,
        # so they will get automatically removed after they expire. We will set
        # everything to be automatically removed shortly after the token expires
        accessJTI = get_jti(encoded_token=access_token)
        refreshJTI = get_jti(encoded_token=refresh_token)
        revokedStore.set(accessJTI, 'false', ACCESS_EXPIRES * 1.2)
        revokedStore.set(refreshJTI, 'false', REFRESH_EXPIRES * 1.2)

        ret['access_token'] = access_token
        ret['refresh_token'] = refresh_token
        ret['phone'] = phone
        return jsonify(ret), 200
    else:
        print("User already exists")
        # Send back error
        if errNum == 1:
            emailMsg = "Email already exists."
            return jsonify({"error": emailMsg}), 400
        else:
            phoneMsg = "Phone number already exists."
            return jsonify({"error": phoneMsg}), 400


@app.route('/user/<int:userID>', methods=["GET", "PUT"])
@jwt_required()
def userInfo(userID):
    """
    Get or update user info.
    Return user info and status 200 OK if user is found, both for
    GET and PUT.
    Return 204 No Content is user not found.
    Return 400 Bad Request otherwise.
    Expected JSON for updating user info:
    {
        "firstName": "John",
        "lastName": "Smith",
        "phone": 1234567890,
        "email": "johnsmith@email.com",
        "mobilePlatform": "iOS"
    }
    """

    user = users.query.get(userID)

    if user == None:
        return jsonify({"result": "User not found"}), 204

    if rq.method == "GET":
        # Get the caregiver or caregivee IDs to add to the user info return
        userDict = user.toJSON()
        cgvr = caregiver.query.filter(caregiver.userID == user.userID).first()
        cgvee = caregivee.query.filter(caregivee.userID == user.userID).first()

        if cgvr is not None:
            userDict["caregiverID"] = cgvr.caregiverID
        elif cgvee is not None:
            userDict["caregiveeID"] = cgvee.caregiveeID
            userDict["physName"] = cgvee.physName
            userDict["physPhone"] = cgvee.physPhone
            # userDict["physStreet"] = cgvee.physStreet
            # userDict["physCity"] = cgvee.physCity
            # userDict["physState"] = cgvee.physState
            # userDict["physZip"] = cgvee.physZip
            

        print("Requesting user info:")
        print(userDict)

        return jsonify({"user": userDict}), 200

    elif rq.method == "PUT":
        incoming = rq.get_json()

        user.firstName = incoming.get("firstName")
        user.lastName = incoming.get("lastName")
        user.phone = incoming.get("phone")
        user.email = incoming.get("email")
        user.mobilePlatform = incoming.get("mobilePlatform")

        db.session.commit()

        return jsonify({"user": user.toJSON()}), 200
    else:
        return "", 400


@app.route('/user/<int:userID>/passwordReset', methods=["PUT"])
@jwt_required()
def passwordReset(userID):
    """
    Reset user's password. 
    Expected JSON:
    {
        "oldPassword": "superSecret",
        "newPassword": "extraSuperSecret"
    }
    """

    user = users.query.get(userID)

    if user == None:
        return jsonify({"result": "User not found"}), 204

    incoming = rq.get_json()

    if bcrypt.check_password_hash(user.password, incoming.get("oldPassword")):
        user.password = bcrypt.generate_password_hash(
            incoming.get("newPassword"))
        db.session.commit()

        return jsonify({"result": "Password updated"}), 200
    else:
        return jsonify({"error": "Old passwords do not match"}), 204

    return "", 400


@app.route('/caregiver/<int:caregiverID>', methods=["GET", "PUT"])
@jwt_required()
def caregiverInfo(caregiverID):
    """
    Get or update caregiver info.
    Return caregiver info and status 200 OK if caregiver is found, both for
    GET and PUT.
    Return 204 No Content is caregiver not found.
    Return 400 Bad Request otherwise. 
    Expected JSON for updating caregiver:
    {
        "caregiverID": 12,
    }
    """

    cgvr = caregiver.query.get(caregiverID)

    if cgvr == None:
        return jsonify({"result": "Caregiver not found"}), 204

    if rq.method == "GET":
        return jsonify({"caregiver": cgvr.toJSON()}), 200
    elif rq.method == "PUT":
        incoming = rq.get_json()

        cgvr.caregiveeID = incoming.get("caregiveeID")

        db.session.commit()

        return jsonify({"caregiver": cgvr.toJSON()}), 200
    else:
        return "", 400


# @app.route('/caregiverFromCaregivee/<caregiveeID>', methods=["GET"])
# @jwt_required()
# def getCaregiverFromCaregivee(caregiveeID):
#     """
#     Get caregiver info based on the caregivee ID
#     Return caregiver info, user info and status 200 OK if caregiver is found
#     Return 204 No Content is caregiver not found.
#     Return 400 Bad Request otherwise. 
#     """
    
#     cgvr = caregiver.query.filter(caregiver.caregiveeID == caregiveeID).first()

#     if cgvr == None:
#         return jsonify({"result": "Caregiver not found"}), 204

#     usr = users.query.get(cgvr.userID)

#     return jsonify({"caregiver": cgvr.toJSON(), "user": usr.toJSON()}), 200


@app.route('/caregivee/create', methods=["POST"])
@jwt_required()
def caregiveeCreationEndpoint():
    """
    Create the caregivee
    Expected JSON: 
    {
        "userID": 13,
        "authCode": "6f6bcab4e53e827a21d8b94739f054b867889e18",
        "caregiverID": 21
    }
    """

    incoming = rq.get_json()
    print(incoming)

    usr = users.query.filter(users.userID == incoming["userID"]).first()

    if usr is None:
        return jsonify({"error": "User not found"}), 204

    caregiveeID = createCaregivee(incoming['authCode'], incoming['userID'] )
                                # incoming['physName'], incoming['physEmail'], incoming['physNum'])
    print("Created Caregivee")

    if caregiveeID == 0:
        return jsonify({'error_0': 'URI mismatch or another problem occured. Check logs for details.'})
    elif (caregiveeID == 1):
        return jsonify({'error_1': "Caregivee has been created before but there was a problem so its not a valid caregivee yet."}), 400
    else:
        if usr.authPhase == 6:
            usr.authPhase = 7
            db.session.commit()

        if incoming["caregiverID"] != None:
            cgver = caregiver.query.filter(caregiver.caregiverID == incoming["caregiverID"]).first()
            if cgver != None:
                cgverUser = users.query.filter(users.userID == cgver.userID).first()
                if cgverUser != None:
                    if cgverUser.authPhase == 3:
                        cgverUser.authPhase = 4
                        db.session.commit()
        return jsonify({'caregiveeID': caregiveeID}), 200
        


@app.route('/caregivee/<caregiveeID>', methods=["GET", "PUT"])
@jwt_required()
def caregiveeInfo(caregiveeID):
    """
    Get or update caregivee info.
    Return caregivee info and status 200 OK if caregivee is found, both for
    GET and PUT.
    Return 204 No Content is caregivee not found.
    Return 400 Bad Request otherwise.
    """

    cgvee = caregivee.query.get(caregiveeID)

    if cgvee == None:
        return jsonify({"result": "Caregivee not found"}), 204

    if rq.method == "GET":
        return jsonify({"caregivee": cgvee.toJSON()}), 200
    elif rq.method == "PUT":
        incoming = rq.get_json()

        cgvee.monitoring = incoming["monitoring"]
        cgvee.recordHR = incoming["recordHR"]
        cgvee.recordSteps = incoming["recordSteps"]
        cgvee.recordDeviceData = incoming["recordDeviceData"]
        cgvee.sleep = incoming["sleep"]
        cgvee.doNotDisturb = incoming["doNotDisturb"]
        # cgvee.healthProfile = incoming["healthProfile"]

        db.session.commit()

        return jsonify({"caregivee": cgvee.toJSON()}), 200
    else:
        return jsonify({"error": "Invalid method. Accepted methods: GET, PUT"}), 400


@app.route('/activity/<caregiveeID>/<int:level>/<int:caregiverID>', methods=["PUT"])
@jwt_required()
def setActivityLevels(caregiveeID, level, caregiverID):
    """
    Set caregivee thresholds based on preset activity levels
    Defaults:
    Active 
    Level 1
    -------
    lowHRThreshold: 50 bpm
    highHRThreshold: 130 bpm
    timeWithoutHRThreshold: 1 hour
    stepThreshold: 625 per hour
    timeWithoutStepsThreshold: 1 hours
    Sedentary 
    Level 2
    ---------
    lowHRThreshold: 60 bpm
    highHRThreshold: 120 bpm
    timeWithoutHRThreshold: 1 hour
    stepThreshold: 312 per hour
    timeWithoutStepsThreshold: 2 hours
    Homebound 
    Level 3
    ---------
    lowHRThreshold: 60 bpm
    highHRThreshold: 100 bpm
    timeWithoutHRThreshold: 1 hour
    stepThreshold: 156 per hour
    timeWithoutStepsThreshold: 4 hours
    """

    print("SETTING ACTIVITY LEVEL")
    print("caregiveeID: " + caregiveeID)

    cgvee = caregivee.query.get(caregiveeID)
    cgver = caregiver.query.get(caregiverID)

    if cgvee is None:
        print("Error setting activity level: caregivee " +
              caregiveeID + " not found")
        return jsonify({"error": "Caregivee not found"}), 204
    if cgver is None:
        print("Error finding caregiver: caregiver " +
              str(caregiverID) + " not found")
        return jsonify({"error": "Caregiver not found"}), 204
    
    usr = users.query.filter(users.userID == cgver.userID).first()
    if usr.authPhase == 5:
        usr.authPhase = 2
        db.session.commit()

    highAndLowRates = connections.query.filter(connections.caregiveeID == caregiveeID, 
                        connections.caregiverID == caregiverID).first()

    if highAndLowRates == None:
        print("Connections not found between {} and {}".format(caregiveeID, caregiverID))
        return jsonify({"error": "Connection not found."})

    if level == 1:
        lowHRThreshold = 50
        highHRThreshold = 130
        timeWithoutHRThreshold = 1
        stepThreshold = 625
        timeWithoutStepsThreshold = 1
        print("Set activity level 1 for " + caregiveeID + " " + str(caregiverID))
    elif level == 2:
        lowHRThreshold = 60
        highHRThreshold = 120
        timeWithoutHRThreshold = 1
        stepThreshold = 312
        timeWithoutStepsThreshold = 2
        print("Set activity level 2 for " + caregiveeID + " " + str(caregiverID))
    elif level == 3:
        lowHRThreshold = 60
        highHRThreshold = 100
        timeWithoutHRThreshold = 1
        stepThreshold = 156
        timeWithoutStepsThreshold = 4
        print("Set activity level 3 for " + caregiveeID + " " + str(caregiverID))
    else:
        print("Invalid activity level " + level + " for " + caregiveeID)
        return jsonify({"error": "Invalid activity level. Accepted values are 1, 2, 3"}), 400

    highAndLowRates.healthProfile = level
    highAndLowRates.lowHRThreshold = lowHRThreshold
    highAndLowRates.highHRThreshold = highHRThreshold
    highAndLowRates.timeWithoutHRThreshold = timeWithoutHRThreshold
    highAndLowRates.stepThreshold = stepThreshold
    highAndLowRates.timeWithoutStepsThreshold = timeWithoutStepsThreshold

    db.session.commit()
    return "", 200


@app.route('/caregivee/<caregiveeID>/<metric>/recent', methods=["GET"])
@jwt_required()
def getHealthDataRecent(caregiveeID, metric):
    """
    Return the most recent user data since the last time this endpoint was called.
    The metric value should be "heart", "steps", "device", or "all".
    Also return 200 OK code for success, 204 No Content if no data is not found,
    or 400 Bad Request otherwise.
    The measurement tables will have lots of entries for the caregivee (as well
    as other caregivees). So for the heart and step data, we want to find the 
    record that matches the caregiveeID, but also has the largest primary key. 
    That will give us the most recent entry.
    """

    print("*-*-*-*-*-*-* RECENT ENDPOINT CALLED FOR CAREGIVEE " +
          caregiveeID + " FOR " + metric + " *-*-*-*-*-*-*-*-*-*")

    today = datetime.now(timezone("US/Eastern")).date()
    yesterday = today - timedelta(days=1)
    currentTime = datetime.now(timezone("US/Eastern")).time()
    currentTimeMinus60Mins = (datetime.combine(
        today, currentTime) - timedelta(minutes=60)).time()
    currentHour = datetime.now(timezone("US/Eastern")).hour

    id = caregiveeID
    heart = None
    hourlyStepQuery = None
    device = None
    dailySteps = 0
    try:
        if metric == "all" or metric == "heart":
            heart = heartRate.query.filter(heartRate.caregiveeID == id, heartRate.date == today).order_by(heartRate.timeMeasured.desc()).first()
            
        # step = steps.query.filter(steps.caregiveeID == caregiveeID, steps.date == today).first()
        if metric == "all" or metric == "device":
            device = fitbit.query.filter(fitbit.caregiveeID == id).first()
        # print(device.toJSON())

        # Calculate and set the daily average heart rate, and set the min and max rates
        # *** Commented out. For now just returns latest average ***
        # dailyHRAverage = db.session.query(func.avg(heartRate.average).label("average")).filter(
        #     heartRate.caregiveeID == caregiveeID).filter(heartRate.date == today).scalar()
        # if dailyHRAverage is None:
        #     dailyHRAverage = 0
        # else:
        #     dailyHRAverage = math.floor(dailyHRAverage)

        # if heart is not None:
            # heart.average = dailyHRAverage
            # # heart.setMinMax(highAndLowRates.currentDayLowHR,
            # #                 highAndLowRates.currentDayHighHR)
            # db.session.commit()

        # Get the step entry and also retrieve daily steps from another fitbit endpoint for daily step accuracy.
        # Consider changing to getStepData() for daily steps but may need to change database structure.
        if metric == "all" or metric == "steps":
            hourlyStepQuery = steps.query.filter(steps.caregiveeID == id).order_by(steps.date.desc()).first()
            cgvee = caregivee.query.filter(caregivee.caregiveeID == id).first()

            accessToken = cgvee.fitbitAccessToken

            authHeader = "Bearer " + accessToken
            requestHeaders = {
                "Content-Type": "application/x-www-form-urlencoded", "Authorization": authHeader}
            urlBase = "https://api.fitbit.com/1/user/"
            url = urlBase + id + "/activities/date/" + str(today) + ".json"

            responseFromFitbit = requests.get(url, headers=requestHeaders)

            responseJson = responseFromFitbit.json()
            summary = responseJson.get("summary")
            print(responseFromFitbit)
            print(responseJson)
            print(summary)
            dailySteps = summary["steps"]
            print(dailySteps)

        # stepRet = hourlyStepQuery

        # if hourlyStepQuery != None:
        #     currentTime = datetime.combine(date.min, currentTime) - datetime.min
        #     t1 = datetime.combine(date.min, hourlyStepQuery.hourlyTime) - datetime.min
        #     difference = (currentTime - t1).total_seconds() / 3600
        #     if difference > 1:
        #         # hourlyStepQuery.hourlyTime = currentTime
        #         hourlyStepQuery.hourlyTotal = 0
        #         stepRet.hourlyTotal = 0
        #         db.session.commit()

        heartJSON = None if heart is None else heart.toJSON()
        stepJSON = None if hourlyStepQuery is None else hourlyStepQuery.toJSON()
        deviceJSON = None if device is None else device.toJSON()

        if metric == "heart":
            return jsonify({"heart": heartJSON}), 200

        if metric == "steps":
            stepJSON["currentDayTotal"] = dailySteps
            return jsonify({"steps": stepJSON}), 200

        if metric == "device":
            return jsonify({"device": deviceJSON}), 200

        if metric == "all":
            # print(type(heart))
            # print(type(hourlyStepQuery))
            # print(type(device))
            stepJSON["currentDayTotal"] = dailySteps
            return jsonify({"heart": heartJSON, "steps": stepJSON, "device": deviceJSON}), 200
        
    except Exception as e:
        return jsonify({"error": "Problem with metric: {}".format(str(e))}), 400
    

    


@app.route('/caregivee/<caregiveeID>/<metric>/<date>', methods=["GET"])
@jwt_required()
def getHealthDataByDate(caregiveeID, metric, date):
    """
    Return all user data for a specified date. The date should be receieved in 
    the YYYY-MM-DD format. The metric value should be "heart" or "steps."
    Also return 200 OK code for success or 400 Bad Request otherwise.
    """

    selectedDate = datetime.strptime(date, "%Y-%m-%d").date()

    if metric == "heart":
        results = [r.toJSON() for r in heartRate.query.filter(heartRate.caregiveeID == caregiveeID).filter(
            heartRate.date == selectedDate).order_by(heartRate.timeMeasured)]

    if metric == "steps":
        results = [r.toJSON() for r in steps.query.filter(steps.caregiveeID == caregiveeID).filter(
            steps.date == selectedDate).order_by(steps.timeMeasured)]

    return jsonify({metric: results}), 200


@app.route('/caregivee/<caregiveeID>/<metric>/<startDate>/<endDate>', methods=["GET"])
@jwt_required()
def getHealthDataByDateRange(caregiveeID, metric, startDate, endDate):
    """
    Return all user data for a specified range of dates. This will allow the
    viewing of historical data. The dates should be receieved in 
    the YYYY-MM-DD format. The metric value should be "heart" or "steps."
    Also return 200 OK code for success or 400 Bad Request otherwise.
    """

    selectedStartDate = datetime.strptime(startDate, "%Y-%m-%d").date()
    selectedEndDate = datetime.strptime(endDate, "%Y-%m-%d").date()

    if metric == "heart":
        results = [r.toJSON() for r in heartRate.query.filter(heartRate.caregiveeID == caregiveeID).filter(or_(
            heartRate.date == selectedStartDate, heartRate.date == selectedEndDate)).order_by(heartRate.date).order_by(heartRate.timeMeasured)]

    if metric == "steps":
        results = [r.toJSON() for r in steps.query.filter(steps.caregiveeID == caregiveeID).filter(or_(
            steps.date == selectedStartDate, steps.date == selectedEndDate)).order_by(steps.date).order_by(steps.timeMeasured)]

    return jsonify({metric: results}), 200


@app.route('/thresholds/<caregiveeID>/<int:caregiverID>', methods=["GET", "PUT"])
@jwt_required()
def getOrSetThresholds(caregiveeID, caregiverID):
    """
    Get or set caregivee thresholds.
    If GET, return thresholds
    If PUT, set thresholds.
    Expected PUT JSON:
    {
        "lowHRThreshold": 60,
        "highHRThreshold": 120,
        "stepThreshold": 3000,
        "timeWithoutHRThreshold": 1,
        "timeWithoutStepsThreshold": 1,
        "sendNoSync": 1,
        "sendNoBattery": 0
    }
    time without are measured in hours
    """
    highAndLowRates = connections.query.filter(connections.caregiveeID == caregiveeID, connections.caregiverID == caregiverID).first()

    if highAndLowRates is None:
        return jsonify({"error": "Caregivee and caregiver connection does not exist"}), 400

    if rq.method == "GET":
        return jsonify({"thresholds": highAndLowRates.toJSON(), "activityLevel": highAndLowRates.healthProfile})
    elif rq.method == "PUT":
        incoming = rq.get_json()

        highAndLowRates.healthProfile = 4
        highAndLowRates.lowHRThreshold = incoming["lowHRThreshold"]
        highAndLowRates.highHRThreshold = incoming["highHRThreshold"]
        highAndLowRates.stepThreshold = incoming["stepThreshold"]
        highAndLowRates.timeWithoutHRThreshold = incoming["timeWithoutHRThreshold"]
        highAndLowRates.timeWithoutStepsThreshold = incoming['timeWithoutStepsThreshold']
        highAndLowRates.sendNoSync = incoming["sendNoSync"]
        highAndLowRates.sendNoBattery = incoming["sendNoBattery"]


        db.session.commit()
        return jsonify({"thresholds": highAndLowRates.toJSON(), "activityLevel": highAndLowRates.healthProfile}), 200
    else:
        return "", 400


@app.route('/messages/<int:userID1>/<int:userID2>', methods=["GET", "POST"])
@jwt_required()
def messageGetOrSend(userID1, userID2):
    """
    Endpoint for handling the quick chat feature. 
    If GET: return all messages between the two users, sorted by timeStamp
    If POST: userID1 is recipient, userID2 is sender. Add message to DB
    Expected POST JSON:
    {
        "timeStamp": "2019-03-04 12:27:32",
        "messageBody": "Just checking in. How is everything?"
    }
    """

    if rq.method == "GET":
        results = [m.toJSON() for m in messages.query.filter(or_(and_(messages.recipient == userID1, messages.sender == userID2), and_(
            messages.recipient == userID2, messages.sender == userID1))).order_by(messages.timeStamp)]
        return jsonify({"messages": results})

    elif rq.method == "POST":
        incoming = rq.get_json()
        print("Sending chat message:")
        print(incoming)

        msg = messages(None, userID1, userID2, datetime.strptime(
            incoming["timeStamp"], "%Y-%m-%d %H:%M:%S"), incoming["messageBody"], 0)
        db.session.add(msg)
        db.session.commit()
        sendChatNotification(userID1, userID2, incoming["messageBody"])

        return "", 201
    else:
        return "", 400


@app.route('/messages/mark/<int:messageID>', methods=["PUT"])
@jwt_required()
def markMessageRead(messageID):
    """
    Mark a chat message as read
    """
    msg = messages.query.get(messageID)

    if msg is None:
        return jsonify({"error": "messageID does not exist"}), 204

    print("Marking chat message read")

    msg.messageRead = 1
    db.session.commit()
    return "", 200


@app.route('/notificationToken/<userId>/<token>', methods=["POST"])
@jwt_required()
def updateNotificationToken(userId, token):
    """
    Update device token for user
    """

    currentUser = users.query.filter(users.userID == userId).first()

    if currentUser is None:
        # Do nothing
        return jsonify({"error": "No user for user ID"}), 200
    else:
        print("Update Token")
        print("userID: " + str(userId))
        print("Token: " + token)
        currentUser.messageToken = token

    db.session.commit()
    return "", 200


@app.route('/tokenRefresh', methods=["POST"])
@jwt_required(refresh=True)
def tokenRefresh():
    """
    Get new access token with refresh token
    """
    currentUser = get_jwt_identity()
    accessToken = create_access_token(identity=currentUser)
    refreshToken = create_refresh_token(identity=currentUser)

    ret = {
        'access_token': accessToken,
        'refresh_token': refreshToken
    }

    accessJTI = get_jti(encoded_token=accessToken)
    refreshJTI = get_jti(encoded_token=refreshToken)
    revokedStore.set(accessJTI, 'false', ACCESS_EXPIRES * 1.2)
    revokedStore.set(refreshJTI, 'false', REFRESH_EXPIRES * 1.2)

    return jsonify(ret), 200


@app.route('/noSyncAlert/<caregiveeID>', methods=["POST"])
@jwt_required()
def noSyncAlert(caregiveeID):
    """
    For monitoring if a fitbit has not synced, we would need a constantly running
    process, which we can't do on the backend. So the front end apps will 
    montior this, and then hit this end point when a notification needs to be 
    sent
    """
    cgvee = caregivee.query.get(caregiveeID)

    # Make sure the caregivee isn't sleeping or in do not disturb mode. No need
    # to send this notifications if so
    if cgvee.doNotDisturb != 1 and cgvee.sleep != 1:
        sendPushNotificationAll(
            caregiveeID, "No Sync", "'s Fitbit has not synced in over an hour", "noSyncAlert")
        return "", 200
    else:
        return jsonify({"response": "Caregivee is in doNotDisturb or sleep mode. Notifcation will not be sent."}), 201


@app.route('/alerts/<caregiveeID>/<int:caregiverID>', methods=["GET"])
@jwt_required()
def getAlerts(caregiveeID, caregiverID):
    """
    Get all alert notifications for a particular caregivee/caregiver connection
    """
    # today = datetime.now(timezone("US/Eastern"))
    # midNight = datetime.min.time()
    # limit = datetime.combine(today, midNight)
    
    notifications = [a.toJSON() for a in alerts.query
        .filter(alerts.caregiveeID == caregiveeID)
        .filter(alerts.caregiverID == caregiverID)]
    print("Attempting to get alerts for " + caregiveeID)

    return jsonify({"alerts": notifications}), 200

@app.route('/alertCounter/<caregiveeID>/<int:caregiverID>', methods=["GET"])
@jwt_required()
def countAlerts(caregiveeID, caregiverID):
    """
    get a counter for all alert notifications for a particular caregivee/caregiver connection
    """
    today = datetime.now(timezone("US/Eastern"))
    midNight = datetime.min.time()
    limit = datetime.combine(today, midNight)
    
    notifications = [a.toJSON() for a in alerts.query
        .filter(alerts.caregiveeID == caregiveeID)
        .filter(alerts.dateTime >= limit)
        .filter(alerts.caregiverID == caregiverID)]
    print("Attempting to count alerts for " + caregiveeID)

    countAlert = len(notifications)

    return jsonify({"counter": countAlert}), 200

@app.route('/lastSyncAlert/<caregiveeID>/<newvalue>', methods=["GET", "PUT"])
@jwt_required()
def syncTime(caregiveeID, newvalue):
    """
        IF GET: get last sync alert and ignore newvalue
        IF PUT: update new last sync alert with new value
    """
    device = fitbit.query.filter(fitbit.caregiveeID == caregiveeID).first()
    newTime = newvalue
    if device == None:
        return jsonify({"result": "Caregivee device not found"}), 204

    if rq.method == "GET":
        return jsonify({"lastSyncAlert": device.lastSyncAlert }), 200
    elif rq.method == "PUT":        
        device.lastSyncAlert = newTime
        db.session.commit()
        return "", 200
    else:
        return jsonify({"error": "Invalid getLastSyncTime method. Accepted methods: GET, PUT"}), 400

@app.route('/alerts/ok/<int:alertID>', methods=["PUT"])
def markAlertOk(alertID):
    """
    Endpoint for the caregivee to mark that an alert is nothing to worry about
    """

    alert = alerts.query.get(alertID)

    if alert is None:
        return jsonify({"error": "alertID does not exist"}), 204

    alert.markOK()
    db.session.commit()

    return "", 200

@app.route('/createRequest', methods=["POST"])
@jwt_required()
def sendRequest():

    """
    What the request body should look like. caregiveeID 

    {
        "caregiveePhone": "5558675309",
        "caregiverPhone": "5558675308",
        "sender": "caregiver"
    }
    
    """

    # Parse json request
    incoming = rq.get_json()
    print(incoming)

    who = incoming["sender"]
    print("who = {}".format(who))

    if (who == None) or (who != "caregiver") and (who != "caregivee"):
        return jsonify({"error":"Sender value not correct."}), 400

    # Check if both phone numbers exist in the database.
    if incoming["caregiveePhone"] and incoming["caregiverPhone"]:

        theCaregiveeCheck = users.query.filter(users.phone == incoming["caregiveePhone"]).first()
        theCaregiverCheck = users.query.filter(users.phone == incoming["caregiverPhone"]).first()

        if theCaregiveeCheck == None:
            return jsonify({"error":"user caregivee doesn't exist."}), 404
        elif theCaregiverCheck == None:
            return jsonify({"error":"user caregiver doesn't exist."}), 404
        
        # Grab the caregivee from caregivee table and caregiver from caregiver table
        cgvee = caregivee.query.filter(caregivee.userID == theCaregiveeCheck.userID).first()
        cgver = caregiver.query.filter(caregiver.userID == theCaregiverCheck.userID).first()

        if cgvee == None:
            return jsonify({"error":"caregivee doesn't exist."}), 404
        if cgver == None:
            return jsonify({"error":"caregiver doesn't exist."}), 404
        
        if theCaregiverCheck.authPhase == 1:
            theCaregiverCheck.authPhase = 2
            db.session.commit()

        # # Check if it is the first caregivee connection.
        # firstCaregivee = connections.query.filter(connections.caregiveeID == cgvee.caregiveeID).first()

        # # Check if it is the first caregiver connection.
        # firstCaregiver = connections.query.filter(connections.caregiverID == cgver.caregiverID).first()

        # Check if the request between the two exists already.
        requestCheck = connections.query.filter(connections.caregiveeID == cgvee.caregiveeID,
                                         connections.caregiverID == cgver.caregiverID).first()
        
        #  if the request doesn't exist already, create one and set defaults as appropriate.
        if requestCheck == None:
            print("Attempting a request creation.")

            # Creates request between a caregiver and caregivee with level 3 health profile as default
            newRequest = connections(None, cgvee.caregiveeID, cgver.caregiverID, "pending", 
                                        incoming["sender"], 0, 0, 60, 100, None, None, 156, 1, 4, cgvee.healthProfile)

            if who == "caregivee":
                cgver.pendingRequestCount += 1
                try:
                    sendRequestNotification (cgver.userID, cgvee.userID)
                except Exception as e:
                    print("send request notificaiton error: {}".format(str(e)))
            else:
                cgvee.pendingRequestCount += 1
                try:
                    sendRequestNotification (cgvee.userID, cgver.userID)
                except Exception as e:
                    print("send request notificaiton error: {}".format(str(e)))
                    
            db.session.add(newRequest)
            db.session.commit()

            # newRequest = connections.query.filter(connections.requestID == newRequest.requestID).first()

            return jsonify({"request": newRequest.toJSON()}), 200

        else:
            return jsonify({"error": "This request already exists"}), 409
        
    else:
        return jsonify({"error":"Incorrect request body."}), 404

# Should be a GET later once passing null or empty strings as parameters is figured out.
@app.route('/getRequests', methods=["POST"])
@jwt_required()
def getUserRequests():
    """
        {
            "caregiveeID": null,
            "caregiverID": 12
        }
        or
        {
            "caregiveeID": "BX9T4W",
            "caregiverID": null
        }
    """

    incoming = rq.get_json()
    print("/getRequest: ", end="")
    print(incoming)

    try:
        # caregivee. returns all caregiver's requesting this caregivee
        if incoming['caregiveeID'] != None and incoming['caregiveeID'] != [] and incoming['caregiverID'] == None and incoming['caregiverID'] != []:

            request = []
            
            for row in connections.query.filter(connections.caregiveeID == incoming['caregiveeID']).all():

                dictRet = dict(row.__dict__)
                dictRet.pop('_sa_instance_state', None)
                # dictRet.pop('caregiveeID', None)
                dictRet.pop('caregiverDefault', None)
                dictRet.pop('caregiveeDefault', None)
                dictRet.pop('currentDayLowHR', None)
                dictRet.pop('currentDayHighHR', None)
                dictRet.pop('lowHRThreshold', None)
                dictRet.pop('highHRThreshold', None)
                dictRet.pop('stepThreshold', None)
                dictRet.pop('timeWithoutHRThreshold', None)
                dictRet.pop('timeWithoutStepsThreshold', None)

                grabCaregiver = caregiver.query.filter(caregiver.caregiverID == row.caregiverID).first()
                caregiverStuff = users.query.filter(users.userID == grabCaregiver.userID).first()

                dictRet["userID"] = grabCaregiver.userID
                dictRet["phone"] = caregiverStuff.phone
                dictRet["firstName"] = caregiverStuff.firstName
                dictRet["lastName"] = caregiverStuff.lastName
                dictRet["email"] = caregiverStuff.email
                # dictRet["pendingRequestCount"] = grabCaregiver.pendingRequestCount

                request.append(dictRet)

            return jsonify({"connections": request}), 200
    
        # caregiver. returns all caregivee's requesting this caregiver
        elif incoming['caregiveeID'] == None and incoming['caregiveeID'] != [] and incoming['caregiverID'] != None and incoming['caregiverID'] != []:

            request = []
            
            for row in connections.query.filter(connections.caregiverID == incoming['caregiverID']).all():
                # grabUser = caregiver.query.filter(caregiver.caregiverID == incoming['caregiverID']).first()
                # user = users.query.filter(users.userID == grabUser.userID).first()

                dictRet = dict(row.__dict__)
                dictRet.pop('_sa_instance_state', None)
                # dictRet.pop('caregiverID', None)
                dictRet.pop('caregiveeDefault', None)
                dictRet.pop('caregiverDefault', None)
                dictRet.pop('currentDayLowHR', None)
                dictRet.pop('currentDayHighHR', None)
                dictRet.pop('lowHRThreshold', None)
                dictRet.pop('highHRThreshold', None)
                dictRet.pop('stepThreshold', None)
                dictRet.pop('timeWithoutHRThreshold', None)
                dictRet.pop('timeWithoutStepsThreshold', None)

                grabCaregivee = caregivee.query.filter(caregivee.caregiveeID == row.caregiveeID).first()
                caregiveeStuff = users.query.filter(users.userID == grabCaregivee.userID).first()

                dictRet["userID"] = grabCaregivee.userID
                dictRet["phone"] = caregiveeStuff.phone
                dictRet["firstName"] = caregiveeStuff.firstName
                dictRet["lastName"] = caregiveeStuff.lastName
                dictRet["email"] = caregiveeStuff.email
                # dictRet["pendingRequestCount"] = grabCaregivee.pendingRequestCount
                # dictRet["healthProfile"] = grabCaregivee.healthProfile

                request.append(dictRet)

            return jsonify({"connections": request}), 200
    except Exception as e:
        print(str(e))
        return jsonify({"error" : str(e)})

    return jsonify({"error": "Wrong format for getting connections"}), 400

@app.route('/setDefaultRequest', methods=["PUT"])
@jwt_required()
def setDefault():
    """
        Gets caregiver and caregivee id's, also needs to know which one we are adjusting for.
        AKA if user is caregiver, caregiver is making B45W9J their caregiverDefault.

        {
            "caregiveeID": "B45W9J",
            "caregiverID": 1,
            "user": "caregiver"
        }
    """

    incoming = rq.get_json()

    cgvee = incoming["caregiveeID"]
    cgver = incoming["caregiverID"]
    user = incoming["user"]
    try:
        if user == 'caregivee':
            # Grabs new request to prepare to set to default caregivee view. Must be an accepted request.
            newDefault = connections.query.filter(connections.caregiveeID == cgvee,
                                    connections.caregiverID == cgver, connections.status == "accepted").first()

            # If null, dont attempt to change.
            if newDefault == None:
                return jsonify({"error": "The connection doesn't exist or has not been accepted."}), 404

            # Grabs old accepted request and changes back to not default if exists.
            oldDefault = connections.query.filter(connections.caregiveeID == cgvee,
                                    connections.caregiveeDefault == 1).first()
            
            if oldDefault != None:
                oldDefault.caregiveeDefault = 0  
            
                      
            newDefault.caregiveeDefault = 1

            db.session.commit()

            return jsonify({"request": newDefault.toJSON()}), 200

        elif user == 'caregiver':

            # Grabs new request and sets to default
            newDefault = connections.query.filter(connections.caregiveeID == cgvee,
                                    connections.caregiverID == cgver).first()

            # If null, dont attempt to change.
            if newDefault == None:
                return jsonify({"error": "The connection doesn't exist."}), 404

            # Grabs old accepted request and changes back to not default.
            oldDefault = connections.query.filter(connections.caregiverID == cgver,
                                    connections.caregiverDefault == 1).first()
            
            if oldDefault == None:
                return jsonify({"error": "The old default connection doesn't exist."}), 404
            
            oldDefault.caregiverDefault = 0
            newDefault.caregiverDefault = 1

            db.session.commit()

            return jsonify({"request": newDefault.toJSON()}), 200
    except:
        return jsonify({"error": "Bad request"}), 400

# accepting a request
@app.route('/acceptRequest', methods=["PUT"])
@jwt_required()
def acceptRequest():

    """
    {
        "caregiveeID": "BXY6JP",
        "caregiverID": 42
    }
    """

    incoming = rq.get_json()

    request = connections.query.filter(connections.caregiveeID == incoming["caregiveeID"],
                                connections.caregiverID == incoming["caregiverID"], connections.status == "pending").first()

    print(request)

    if request == None:
        return jsonify({"error": "Request not found or has already been accepted."}), 404

    else:
        # First accepted request?
        try:
            firstCaregivee = connections.query.filter(connections.caregiveeID == incoming["caregiveeID"],
                                                connections.status == "accepted").first()
            firstCaregiver = connections.query.filter(connections.caregiverID == incoming["caregiverID"],
                                                connections.status == "accepted").first()
            print(firstCaregivee)
            print(firstCaregiver)
            
            setCgveeDefault = 0
            setCgverDefault = 0

            if firstCaregivee == None:
                setCgveeDefault = 1
            if firstCaregiver == None:
                setCgverDefault = 1
            
            print(setCgveeDefault)
            print(setCgverDefault)
            
            request.status = "accepted"
            request.caregiveeDefault = setCgveeDefault
            request.caregiverDefault = setCgverDefault


            cgvee = caregivee.query.filter(caregivee.caregiveeID == incoming["caregiveeID"]).first()
            cgver = caregiver.query.filter(caregiver.caregiverID == incoming["caregiverID"]).first()

            if request.sender == "caregivee":
                cgver.pendingRequestCount -= 1
            else:
                cgvee.pendingRequestCount -= 1

            db.session.commit()

            if setCgveeDefault == 1:
                return jsonify({"caregiver": cgver.toJSON()}), 200
            elif setCgverDefault == 1:
                return jsonify({"caregivee": cgvee.toJSON()}), 200
            elif setCgveeDefault == 1 and setCgverDefault == 1:
                return jsonify({"caregivee": cgvee.toJSON(), "caregiver": cgver.toJSON()}), 200
            return "", 200
        except Exception as e:
            print(str(e))
            return jsonify({"error": str(e)}), 400

@app.route('/deleteRequest/<int:requestID>', methods=["DELETE"])
@jwt_required()
def deleteRequest(requestID):

    request = connections.query.get(requestID)
    if request == None:
        return jsonify({"error": "Request not found"}), 204

    print(request)

    cgveeID = request.caregiveeID
    cgverID = request.caregiverID

    try:
        db.session.delete(request)
        db.session.commit()
        if request.status == "accepted":
            newDefaultCgvee = connections.query.filter(connections.caregiveeID == cgveeID).first()
            newDefaultCgver = connections.query.filter(connections.caregiverID == cgverID).first()

            print(newDefaultCgvee)
            print(newDefaultCgver)

            if newDefaultCgvee != None and newDefaultCgvee.caregiveeDefault != 1 and newDefaultCgver != None and newDefaultCgver.caregiverDefault != 1:
                newDefaultCgvee.caregiveeDefault = 1
                newDefaultCgver.caregiverDefault = 1
                cgvee = caregivee.query.filter(caregivee.caregiveeID == newDefaultCgvee.caregiveeID).first()
                cgver = caregiver.query.filter(caregiver.caregiverID == newDefaultCgver.caregiverID).first()

                db.session.commit()
                return jsonify({"newCaregiver": cgver.toJSON(), "newCaregivee": cgvee.toJSON()}), 200
            elif newDefaultCgvee != None and newDefaultCgvee.caregiveeDefault != 1 and newDefaultCgver == None:
                newDefaultCgvee.caregiveeDefault = 1
                cgver = caregiver.query.filter(caregiver.caregiverID == newDefaultCgvee.caregiverID).first()

                db.session.commit()
                return jsonify({"newCaregiver": cgver.toJSON()}), 200
            elif newDefaultCgver != None and newDefaultCgver.caregiverDefault != 1 and newDefaultCgvee == None:
                newDefaultCgver.caregiverDefault = 1
                cgvee = caregivee.query.filter(caregivee.caregiveeID == newDefaultCgver.caregiveeID).first()

                db.session.commit()
                return jsonify({"newCaregivee": cgvee.toJSON()}), 200
            # Neither has another request to default to.
            else:
                return "", 200
        
        # Request was pending so decrement depending on the sender. Decrement the opposite of who the sender is
        # So if sender is caregivee, decrement the caregiver pendingRequestCount on deletion.
        else:
            if request.sender == "caregivee":
                cgver = caregiver.query.filter(caregiver.caregiverID == request.caregiverID).first()
                cgver.pendingRequestCount -= 1
                db.session.commit()
                return jsonify({"message": f"{str(cgver.caregiverID)}'s pendingRequestCount is {cgver.pendingRequestCount}"})
            elif request.sender == "caregiver":
                cgvee = caregivee.query.filter(caregivee.caregiveeID == request.caregiveeID).first()
                cgvee.pendingRequestCount -= 1
                db.session.commit()
                return jsonify({"message": f"{str(cgvee.caregiveeID)}'s pendingRequestCount is {cgvee.pendingRequestCount}"})
            else:
                return jsonify({"error": "error decrementing the pending request count of caregiver/caregivee."}), 400
        
        
    except Exception as e:
        print(str(e))
        return jsonify({"error": str(e)}), 400

@app.route('/getDefaultRequest', methods=["POST"])
@jwt_required()
def getDefaultRequest():
    """
    {
       "caregiveeID": null,
        "caregiverID": 1 
    }
    {
        "caregiveeID": "B5TWLX",
        "caregiverID": null
    }
    """

    incoming = rq.get_json()
    cgvee = incoming["caregiveeID"]
    cgver = incoming["caregiverID"]

    # Since caregivee is null, we are grabbing caregiverDefault request for caregiver
    if cgvee == '' or cgvee == None:
        try:
            grabCgverDefault = connections.query.filter(connections.caregiverID == cgver,
                                                        connections.caregiverDefault == 1).first()
            
            result = grabCgverDefault

            if result == None:
                return jsonify({"error": "request not found."}), 404
            elif result.status == "pending":
                return jsonify({"error": "request not accepted."}), 400

            cgveeInfo = caregivee.query.filter(caregivee.caregiveeID == grabCgverDefault.caregiveeID).first()
            userInfo = users.query.filter(users.userID == cgveeInfo.userID).first()
            
            dictRet = dict(grabCgverDefault.__dict__)

            dictRet.pop('_sa_instance_state', None)
            dictRet.pop('caregiverID', None)
            dictRet.pop('caregiveeDefault', None)
            dictRet.pop('caregiverDefault', None)
            dictRet.pop('requestID', None)
            dictRet.pop('status', None)
            dictRet.pop('sender', None)
            dictRet.pop('currentDayLowHR', None)
            dictRet.pop('currentDayHighHR', None)
            dictRet.pop('lowHRThreshold', None)
            dictRet.pop('highHRThreshold', None)
            dictRet.pop('stepThreshold', None)
            dictRet.pop('timeWithoutHRThreshold', None)
            dictRet.pop('timeWithoutStepsThreshold', None)

            dictRet["email"] = userInfo.email
            dictRet["firstName"] = userInfo.firstName
            dictRet["lastName"] = userInfo.lastName
            dictRet["phone"] = userInfo.phone
            dictRet["userID"] = cgveeInfo.userID
            dictRet["physName"] = cgveeInfo.physName
            dictRet["physPhone"] = cgveeInfo.physPhone
            dictRet["physPhone"] = cgveeInfo.physPhone
            
            return jsonify({"default": dictRet}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # grab caregivee's default.
    elif cgver == '' or cgver == None:
        try:
            grabCgveeDefault = connections.query.filter(connections.caregiveeID == cgvee,
                                                    connections.caregiveeDefault == 1).first()

            result = grabCgveeDefault

            if result == None:
                return jsonify({"error": "request not found."}), 404
            elif result.status == "pending":
                return jsonify({"error": "request not accepted."}), 400

            cgverInfo = caregiver.query.filter(caregiver.caregiverID == grabCgveeDefault.caregiverID).first()
            userInfo = users.query.filter(users.userID == cgverInfo.userID).first()

            dictRet = dict(grabCgveeDefault.__dict__)

            dictRet.pop('_sa_instance_state', None)
            dictRet.pop('caregiveeID', None)
            dictRet.pop('caregiverDefault', None)
            dictRet.pop('caregiveeDefault', None)
            dictRet.pop('requestID', None)
            dictRet.pop('status', None)
            dictRet.pop('sender', None)
            dictRet.pop('currentDayLowHR', None)
            dictRet.pop('currentDayHighHR', None)
            dictRet.pop('lowHRThreshold', None)
            dictRet.pop('highHRThreshold', None)
            dictRet.pop('stepThreshold', None)
            dictRet.pop('timeWithoutHRThreshold', None)
            dictRet.pop('timeWithoutStepsThreshold', None)

            dictRet["email"] = userInfo.email
            dictRet["firstName"] = userInfo.firstName
            dictRet["lastName"] = userInfo.lastName
            dictRet["phone"] = userInfo.phone
            dictRet["userID"] = cgverInfo.userID
            
            return jsonify({"default": dictRet}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    else:
        return jsonify({"error": "Bad request"}), 400    

# @app.route('/acceptCaregiverRequest', methods=["POST"])
# def acceptCaregiverRequest():
    """
    Once the app catches the caregiver and caregivee IDs after the user clicks
    the Accept Request button in the email, the front end will take those
    IDs and hit this endpoint to complete the process.
    Expected JSON:
    {
        "caregiver": caregiverID,
        "caregivee": caregiveeID
    }
    """
    incoming = rq.get_json()
    print(incoming)
    cgvr = caregiver.query.filter(
        caregiver.caregiverID == incoming["caregiver"]).first()
    cgvee = caregivee.query.filter(
        caregivee.caregiveeID == incoming["caregivee"]).first()
    cgveeUser = users.query.get(cgvee.userID)

    print("Caregiver requesting: " + str(cgvr.caregiverID))
    print("Caregive accepting: " + cgvee.caregiveeID)
    print(cgveeUser.firstName)

    cgvr.caregiveeID = cgvee.caregiveeID
    db.session.commit()

    # Let the caregiver know the request has been accepted
    sendPushNotification(cgvee.caregiveeID, "Caregiving Request Accepted",
                         " has accepted the request to be caregivee", "requestAccepted")

    return "", 200

@app.route("/physician", methods=["PUT"])
@jwt_required()
def physician():
    """
        {
            "caregiveeID": "BXY6D3",
            "physName": "Richard Reed",
            "physPhone": "1234567890",
            "physStreet": "123 Main Street",
            "physCity": "Orlando",
            "physState": "Florida",
            "physZip": "32817",
            "caregiverID": 12
        }
    
    """

    incoming = rq.get_json()

    cgvee = caregivee.query.get(incoming["caregiveeID"])
    print(cgvee)

    if cgvee is None:
        return jsonify({"error": "Caregivee not found"}), 204
    
    if incoming["caregiverID"] != None:
        cgver = caregiver.query.filter(caregiver.caregiverID == incoming["caregiverID"]).first()
        usr = users.query.filter(users.userID == cgver.userID).first()

        if usr != None:
            if usr.authPhase == 4:
                usr.authPhase = 5
                db.session.commit()
        else:
            return jsonify({"error": "Caregiver not found in user table."}), 400

    usr = users.query.filter(users.userID == cgvee.userID).first()
    if usr != None:
        if usr.authPhase == 7:
            usr.authPhase = 8
            db.session.commit()
    else:
        return jsonify({"error": "Caregivee not found in the users table."}), 204

    cgvee.physName = incoming.get("physName")
    cgvee.physPhone = incoming.get("physPhone")
    # cgvee.physStreet = incoming.get("physStreet")
    # cgvee.physCity = incoming.get("physCity")
    # cgvee.physState = incoming.get("physState")
    # cgvee.physZip = incoming.get("physZip")

    db.session.commit()

    return jsonify({"cgvee": cgvee.toJSON()}), 200

@app.route("/getFitbitToken/<caregiveeID>", methods=["GET"])
@jwt_required()
def getToken(caregiveeID):

    theCaregivee = caregivee.query.get(caregiveeID)

    if theCaregivee == None:
        return jsonify({"error": "Caregivee not found."})
    
    return jsonify({"fitbitToken": theCaregivee.fitbitAccessToken})

@app.route("/refreshFitbitToken/<caregiveeID>", methods=["GET"])
@jwt_required()
def refreshToken(caregiveeID):
    cgvee = caregivee.query.get(caregiveeID)
    if cgvee == None:
        return jsonify({"error": "Caregivee not found"}), 400
    
    response = refreshAccessToken(cgvee)
    if response == None:
        return jsonify({"error": "No response from fitbit"}), 400

    cgvee.fitbitAccessToken = response.get("access_token")
    cgvee.fitbitRefreshToken = response.get("refresh_token")
    db.session.commit()
    
    return response, 200

@app.route("/updateHealthProfile", methods=["PUT"])
@jwt_required()
def updateHP():
    """
        "caregiveeID": "BXY6T7",
        "healthProfile": "",
        "caregiverID": 12
    """
    incoming = rq.get_json()

    hp = int(incoming["healthProfile"])
    cgveeID = incoming["caregiveeID"]

    if hp < 1 or hp > 3:
        return jsonify({"error": "Not correct range of health profile."}), 400
    
    try:
        cgvee = caregivee.query.filter(caregivee.caregiveeID == cgveeID).first()
        cgvee.healthProfile = hp
        db.session.commit()

        for row in connections.query.filter(connections.caregiveeID == cgveeID).all():
            if row.healthProfile == None:
                row.healthProfile = hp
                db.session.commit()
        if incoming["caregiverID"] != None:
            cgver = caregiver.query.filter(caregiver.caregiverID == incoming["caregiverID"]).first()
            usr = users.query.filter(users.userID == cgver.userID).first()
            
            if usr.authPhase == 5:
                usr.authPhase = 2
                db.session.commit()
        usr = users.query.filter(users.userID == cgvee.userID).first()
        if usr.authPhase == 8:
            usr.authPhase = 9
            db.session.commit()
    except Exception as e:
        return jsonify({"error": str(e)})
    
    return "", 200

@app.route("/getRequestCount/<ID>", methods=["GET"])
@jwt_required()
def getRequestCount(ID):
    print(ID)
    # Try caregiver decrement first and if value error, do caregivee. if no match either way, return error
    try:
        cgverID = int(ID)
        cgver = caregiver.query.get(cgverID)
        print(cgver)
        if cgver == None:
            return jsonify({"error": "caregiver not found."}), 400
        return jsonify({"pendingRequestCount": cgver.pendingRequestCount}), 201
    except ValueError:
        cgveeID = ID
        cgvee = caregivee.query.get(cgveeID)
        if cgvee == None:
            return jsonify({"error": "caregivee not found."}), 400
        print(cgvee)
        return jsonify({"pendingRequestCount": cgvee.pendingRequestCount}), 201
    except AttributeError as e:
        return jsonify({"error": str(e)}), 400

# Searches for a phone number stored in the caregivee table in the optNumber field.
# Not being null means there is a caregivee stored as an opt out. Limit 1.
@app.route("/optCaregivee", methods=["POST", "PUT"])
@jwt_required()
def getCaregiveeWithPhone():
    # For PUT request.
    """
        "caregiverID": 12,
        "phone": "6398563492"
    """
    # POST
    """
        "caregiverID": 12
    """
    # print(rq.get_json())
    try:
        incoming = rq.get_json()
        
        # Attempt to check for a phone number stored in the caregiver entry for that caregiverID
        if rq.method == "POST":
            cgver = caregiver.query.filter(caregiver.caregiverID == incoming["caregiverID"]).first()
            if cgver.optNumber == None:
                return jsonify({"message": "No opt-out number stored for caregiver."}), 200

            else:
                cgveeUserInfo = users.query.filter(users.phone == cgver.optNumber).first()

                if cgveeUserInfo == None:
                    return jsonify({"error": "No caregivee stored as opt-out with that phone number."}), 404
                else:
                    cgvee = caregivee.query.filter(caregivee.userID == cgveeUserInfo.userID).first()
                    cgveeID = None if cgvee == None else cgvee.caregiveeID
                    return jsonify({"caregivee": cgveeUserInfo.toJSON(), "caregiveeID": cgveeID}), 200
        # Attempt to set the optNumber
        else:
            
            cgvee = caregiver.query.filter(caregiver.caregiverID == incoming["caregiverID"]).first()
            print(cgvee.optNumber)
            print(cgvee.toJSON())

            cgvee.optNumber = incoming["phone"]
            db.session.commit()

            return "", 200
    # This should be less generic: bad practice generally to catch all and handle the same way.
    except Exception as e:
        return jsonify({"error": str(e)}), 400

###############################################################################
#                    Main Page Endpoint and Main Function                     #
###############################################################################


@app.route('/')
def root():
    """
    Main page for the web interface. The only thing there is the Fitbit OAuth 
    process used for testing
    """
    return app.send_static_file('index.html')


@app.route('/accept')
def accept():
    return app.send_static_file('accept.html')


if __name__ == "__main__":
    app.run(debug=False)