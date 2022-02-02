# -*- coding:  utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from carers_app.models import *
from carers_app.models import Invoice as Invoices
from django.contrib.auth.models import Group as UserGroup
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
import hashlib, random, datetime, base64, reportlab, json, string
from django.utils import timezone
from django.conf import settings
from twython import Twython
from django.db.models import Q, Sum
from django.core.urlresolvers import reverse
from twilio.rest import Client
from django.contrib.auth import authenticate,login, logout, update_session_auth_hash
from django.views.generic import TemplateView
from django.views.generic.base import View
from django.db import connection
from carers_app.forms import ProfileForm, ContactForm
from django.contrib import messages
from reportlab.pdfgen import canvas
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.mail import EmailMessage
import requests, re, stripe as stripe, os
from chat.models import Room, UserChat
from django.core.exceptions import ObjectDoesNotExist
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.utils.safestring import mark_safe
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from carers_app.models import STATUS_CHOICES, PAYMENT_CHOICES, CONTRACT_CHOICES
from django.template.loader import get_template
from django.template import Context
from django.shortcuts import render_to_response 
from django.core import exceptions
import pdfkit
import os
import datetime
from datetime import timedelta
from xhtml2pdf import pisa
import sys
import logging
from Crypto.Cipher import AES
import csv
import calendar


reload(sys)
sys.setdefaultencoding('utf8')

stripe.api_key = settings.SECRET_STRIPE_KEY
stripe.api_version = "2020-03-02"

logger = logging.basicConfig(filename="/home/ubuntu/Project/logfilename.log", level=logging.ERROR)
# f = open("customlogger.txt","w+")
# Create your views here.


def home(request):
	
	group = "none"
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	if not request.user.is_anonymous:
		group = UserGroup.objects.get(user = request.user.id).name
	return render(request, 'templates/home.html', {
							'group':group
							})


def about_us(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	about_us = CMSPages.objects.get(id = 1)
	group = ''
	try:
		group = UserGroup.objects.get(user = request.user.id).name
	except:
		pass
	return render(request, 'templates/about_us.html', {
		'page_content': about_us.content,
		'group':group
		})

	
def Faqcarer(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	about_us = CMSPages.objects.get(id = 1)
	group = ''
	try:
		group = UserGroup.objects.get(user = request.user.id).name
	except:
		pass
	return render(request, 'templates/Faqcarer.html', {
		'page_content': about_us.content,
		'group':group
		})


def how_it_works(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	group = ''
	try:
		group = UserGroup.objects.get(user = request.user.id).name
	except:
		pass
	how_it_work = CMSPages.objects.get(id = 2)
	return render(request, 'templates/how_it_works.html',  {
		'page_content': how_it_work.content,
		'group':group
		})


def faq(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	group = ''
	try:
		group = UserGroup.objects.get(user = request.user.id).name
	except:
		pass
	faq = CMSPages.objects.get(id = 3)
	return render(request, 'templates/faq.html',{
		'page_content': faq.content,
		'group':group
		})


def carer(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	group = ''
	try:
		group = UserGroup.objects.get(user = request.user.id).name
	except:
		pass
	carer = CMSPages.objects.get(id = 4)
	return render(request, 'templates/iamcarer.html', {
		'page_content': carer.content,
		'group':group
		})


def terms_conditions(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	group = ''
	try:
		group = UserGroup.objects.get(user = request.user.id).name
	except:
		pass
	termscondition = CMSPages.objects.get(id = 5)
	return render(request, 'templates/terms_conditions.html', {
		'page_content': termscondition.content,
		'group':group
		})


def privacy_policy(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	group = ''
	try:
		group = UserGroup.objects.get(user = request.user.id).name
	except:
		pass
	privacypolicy = CMSPages.objects.get(id = 6)
	return render(request, 'templates/privacy_policy.html',{
		'page_content': privacypolicy.content,
		'group':group
		})	


def signup(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')

	if not request.user.is_anonymous:
		return HttpResponseRedirect("/")

	if request.method == "POST" and "Submit" in request.POST:
		print ">>>>>>>>>>>>>>>>>start from here."
		contct = request.POST['contact_number'].replace(" ","")
		tel = request.POST['telephone_number'].replace(" ","")
		group = request.POST['group']
		first_name = str(request.POST['first_name']).title()
		last_name = str(request.POST['last_name']).title()
		contact_number = contct
		telephone_number = tel
		email = request.POST['email']
		password = request.POST['password']
		group = UserGroup.objects.get(name=group)
		activation_key = base64.b64encode(str(email))
		if request.is_secure():
			link='https://'+str(request.get_host())+"/activate/"+str(activation_key)
		else:
			link='http://'+str(request.get_host())+"/activate/"+str(activation_key)
		try:
			email = User.objects.get(email=email)
			messages.add_message(request, messages.INFO, "This email is already registered with us.\n Please register using another email")
			return HttpResponseRedirect('/signup')
		except:
			print ">>>>>>>>>>>>>>>>>email exists"
			user = User(first_name=first_name, last_name=last_name,
			 email=email, contact_number=contact_number, telephone_number= telephone_number,
			 username= email, is_active=False)
			user.set_password(password)
			user.save()                     
			user.groups.add(group)
			
			if group=="Service Seeker":
				user.publish=True
				user.save()

			user_alert = UserAlert(user=user)
			user_alert.save()
			activation_key = base64.b64encode(str(email))
			
			if request.is_secure():
				link='https://'+str(request.get_host())+"/activate/"+str(activation_key)
				logo_url = 'https://'+str(request.get_host())
			else:
				link='http://'+str(request.get_host())+"/activate/"+str(activation_key)
				logo_url = 'http://'+str(request.get_host())

			print ">>>>>>>>>>>>>>>>>>>>>>>>>>>logo_url"
			template = EmailTemplate.objects.get(id=19)
			email_html = template.content
			
			ctx = {
		        'user':str(user.first_name.title()) +' '+ str(user.last_name.title()),
		        'email': str(user.email),
		        'Mobile_number': str(user.telephone_number),
		        'Phone_number': str(user.contact_number),
		    }

			email_html = string.replace(email_html, '{{USER}}', ctx['user'])
			email_html = string.replace(email_html, '{{EMAIL}}', ctx['email'])
			email_html = string.replace(email_html, '{{MOBILE_NO1}}', ctx['Mobile_number'])
			email_html = string.replace(email_html, '{{MOBILE_NO2}}', ctx['Phone_number'])
			email_html = string.replace(email_html, '{{logo_url}}', logo_url)
		    
			ctx = {
			'getMessage':email_html,
			}
		    
		    # link = get_template('user_email/staff_creation_template.html').render(ctx) 
			
			admin_user = User.objects.filter(is_superuser=1)
			for admin in admin_user:
				try:
					email = admin.email
					subject = 'Carers Direct : New User'
					message =  get_template('templates/email_templates/new_user_template.html').render(ctx)
					msg = EmailMessage(subject, 'message', to= [email], from_email= settings.EMAIL_HOST_USER)
					msg.content_subtype = "html"
					msg.send(fail_silently=False)
				except Exception as error:
					print ">>>>>>>>>>>>>>>>>>>>>>>>>>>new registration2"
					raise

			try:
				template = EmailTemplate.objects.get(id=3)
				email_html = template.content 
				getMessage = string.replace(email_html, '{{url}}', link)
				getMessage = string.replace(getMessage, '{{logo_url}}', logo_url)
				print ">>>>>>>>>>>>>>>>>>>>>>>>>>>get message"
				ctx = {
				'getMessage':getMessage,
				} 
				subject = 'Carers Direct : Activation Email'
				message = get_template('templates/email_templates/emailactivation_template.html').render(ctx)
				msg = EmailMessage(subject, message, to= [user.email], from_email= settings.EMAIL_HOST_USER)
				msg.content_subtype = "html"
				msg.send(fail_silently=False) 
				messages.add_message(request, messages.INFO, "We have successfully sent an activation link to your registered email address. Please activate your account.")
				return HttpResponseRedirect('/signup')
			except:
				print ">>>>>>>>>>>>>>>>>>>>>>>>>>>new registration"
				messages.add_message(request, messages.INFO, "Something went wrong. Please try later.")
				return HttpResponseRedirect('/signup')

		return HttpResponseRedirect("/")

	if request.method == "POST" and "noemailsocial" in request.POST:
		contctfb1 = request.POST['contact_number'].replace(" ","")
		telfb1 = request.POST['mobile_number'].replace(" ","")
		group = request.POST['type']
		first_name = str(request.POST['firstname']).title()
		last_name = str(request.POST['lastname']).title()
		contact_number = contctfb1
		mobile_number = telfb1
		email = request.POST['emailid']
		access_token = request.POST['user_ID']
		group = UserGroup.objects.get(name=group)
		
		try:
			email = User.objects.get(email=email)
			messages.add_message(request, messages.INFO, "This email is already registered with us.\n Please register using another email")
			return HttpResponseRedirect('/signup')
		except:
			user = User(username=email, fb_auth_token=access_token, is_active=True, email=email, contact_number=contact_number, first_name=first_name, last_name=last_name,telephone_number = mobile_number)
			user.set_password(access_token)
			user.save()
			user.groups.add(group)
			if group=="Service Seeker":
				user.publish=True
				user.save()
			user_alert = UserAlert(user=user)
			user_alert.save()
			authenticate(username=user.username, password=user.password)
			login(request, user)
			return HttpResponseRedirect('/dashboard')

	if request.method == "POST" and "emailsocial" in request.POST:
		contctfb2 = request.POST['contactnumber'].replace(" ","")
		telfb2 = request.POST['mobile_number'].replace(" ","")
		group = request.POST['usertype']
		first_name = str(request.POST['f_name']).title()
		last_name = str(request.POST['l_name']).title()
		contact_number = contctfb2
		mobile_number = telfb2
		email = request.POST['email_id']
		access_token = request.POST['userID']
		group = UserGroup.objects.get(name=group)
		try:
			email = User.objects.get(email=email)
			messages.add_message(request, messages.INFO, "This email is already registered with us.\n Please register using another email")
			return HttpResponseRedirect('/signup')
		except:
			user = User(username=email, fb_auth_token=access_token, is_active=True, email=email, contact_number=contact_number, first_name=first_name, last_name=last_name,telephone_number = mobile_number)
			user.set_password(access_token)
			user.save()
			if group=="Service Seeker":
				user.publish=True
				user.save()
			user.groups.add(group)
			user_alert = UserAlert(user=user)
			user_alert.save()
			authenticate(username=user.username, password=user.password)
			login(request, user)
			return HttpResponseRedirect('/dashboard')
			
	if request.method == "POST" and "social_Twitter" in request.POST:
		contctfb2 = request.POST['contact_number'].replace(" ","")
		telfb2 = request.POST['mobile_number'].replace(" ","")
		group = request.POST['type']
		email = request.POST['email']
		firstname = str(request.POST['firstname']).title()
		lastname = str(request.POST['lastname']).title()
		access_token = request.POST['userID']
		contact_number = contctfb2
		mobile_number = telfb2
		#changes by pavan sharma (first name , last name and mobile_number)
		group = UserGroup.objects.get(name=group)
		try:
			email = User.objects.get(email=email)
			messages.add_message(request, messages.INFO, "This email is already registered with us.\n Please register using another email")
			return HttpResponseRedirect('/signup')
		except:
			user = User(first_name=firstname, last_name=lastname,username= email, tw_auth_token=access_token, is_active=True, email=email, contact_number=contact_number,telephone_number = mobile_number)
			user.set_password(access_token)
			user.save()
			if group=="Service Seeker":
				user.publish=True
				user.save()
			user.groups.add(group)
			user_alert = UserAlert(user=user)
			user_alert.save()
			authenticate(username=user.username, password=user.password)
			login(request, user)
			return HttpResponseRedirect('/dashboard')
	secure = "False"
	host = request.get_host()
	redirect_url = "http://"+str(host)+"/dashboard"
	if request.is_secure():
		secure = "True"
		redirect_url = "https://"+str(host)+"/dashboard"
	return render(request, 'templates/signup.html', {'redirect_url': redirect_url})		


def activate(request, key):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	if request.method == "POST":
		already_active = False
		activation_expired = False
		try: 
			activation_key = base64.b64decode(key)
		except: 
			print HttpResponse("This link is invalid")
		try: 
			user = User.objects.get(email=str(activation_key))
			if user.is_active == False: 
				user.is_active = True
				user.save()
				authenticate(username=user.username, password=user.password)
				login(request, user)
				messages.add_message(request, messages.SUCCESS, "Your account has been activated successfully. Please click anywhere on screen to proceed further." )
				return HttpResponseRedirect('/dashboard')
			else: 
				already_active = True
				messages.add_message(request, messages.SUCCESS, "Your link has been expired.Please generate new activation link." )
				return HttpResponseRedirect("/")
		except:
			messages.add_message(request, messages.INFO, "This link is not valid now.")
			return HttpResponseRedirect("/")
		messages.add_message(request, messages.SUCCESS, "Your account has been activated successfully." )
		return HttpResponseRedirect("/login")

	if request.method == "GET":
		try:
			activation_key = base64.b64decode(key)
			user = User.objects.get(email=str(activation_key))
			if user.is_active:
				active = "True"
			else:
				active = "False"	
			return render(request, 'templates/activation.html', {'key': key, 'active': active})
		except:
			messages.add_message(request, messages.INFO, "This link is not valid.")
			return HttpResponseRedirect("/")


def forgot_password(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')

	if request.method == "POST":
		email = request.POST['email']
		try: 
			user = User.objects.get(email=str(email))
			if not user.is_active:
				messages.add_message(request, messages.ERROR, 'Please activate your account first.')
				return HttpResponseRedirect('/forgot_password/')
			user.forgot_password_date = timezone.now()
			user.save()
			encoded_data = base64.b64encode(str(email))
			if request.is_secure():
				link='https://'+str(request.get_host())+"/change_password/"+str(encoded_data)
				logo_url='https://'+str(request.get_host())
			else:
				link='http://'+str(request.get_host())+"/change_password/"+str(encoded_data)
				logo_url='http://'+str(request.get_host())
			
			template = EmailTemplate.objects.get(id=1)
			email_html = template.content 
			getMessage = string.replace(email_html, '{{url}}', link)
			getMessage = string.replace(getMessage, '{{logo_url}}', logo_url)

			ctx = {
			'getMessage':getMessage,
			} 

			subject = 'Carers Direct : Forgot Password'
			message =  get_template('templates/email_templates/forgotpassword_template.html').render(ctx)
			msg = EmailMessage(subject, message, to= [email], from_email= settings.EMAIL_HOST_USER)
			msg.content_subtype = "html"
			msg.send() 
			# changes by pavan
			messages.add_message(request, messages.ERROR, 'An email has been sent to your registered email id')
			return HttpResponseRedirect('/forgot_password/')
		except:
			messages.add_message(request, messages.ERROR, 'Please enter registered email id')
			return HttpResponseRedirect('/forgot_password/')
	return render(request, 'templates/forgotpassword.html') 


def change_password(request, key):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	expired_link = ''
	if str(request.user) != 'AnonymousUser':
		return HttpResponseRedirect("/")
	try: 
		decoded_data = base64.b64decode(key)
	except: 
		expired_link = "Not a valid link."
	try: 
		user = User.objects.get(email=str(decoded_data))
		if timezone.now() > user.forgot_password_date + datetime.timedelta(days=3): 
			expired_link ="Your link has been expired."
		else: 
			pass
	except: 
		expired_link = "This is not a generated link"
	if request.method == "POST":
		try: 
			decoded_data = base64.b64decode(key)
		except: 
			messages.add_message(request, messages.ERROR, "Not a valid url")
			return HttpResponseRedirect(str(request.get_full_path()))
		try: 
			user = User.objects.get(email=str(decoded_data))
			if timezone.now() > user.forgot_password_date + datetime.timedelta(days=3): 
				messages.add_message(request, messages.ERROR, "Your link has been expired.")
				return HttpResponseRedirect(str(request.get_full_path()))
			else:
				password = request.POST['changed_password']
				try:
					user = User.objects.get(email=str(decoded_data))
					user.set_password(password)
					user.save()
					messages.add_message(request, messages.ERROR, 'Your password has been changed. Please login.')
					return HttpResponseRedirect("/login")
				except: 
					pass
		except: 
			messages.add_message(request, messages.ERROR, "This is not a generated link.!")
			return HttpResponseRedirect(str(request.get_full_path()))
		
	return render(request,'templates/reset_password.html',{'expired':expired_link}) 


def check_status(request):
	user_id = request.GET['ID']
	try: 
		user = User.objects.get(Q(fb_auth_token=user_id)|Q(tw_auth_token=user_id))
		result = 'True'
		authenticate(username=user.username, password=user.password)
		login(request, user)
	except: 
		result = 'False'
	data = result
	return HttpResponse(data)


def twitter_login(request):

    host = request.get_host()
    twitter = Twython(
        app_key = settings.TWITTER_KEY,
        app_secret = settings.TWITTER_SECRET,
    )
    if request.is_secure():
    	auth_props = twitter.get_authentication_tokens(callback_url='https://'+str(host)+'/twitter/callback')
    else:
    	auth_props = twitter.get_authentication_tokens(callback_url='http://'+str(host)+'/twitter/callback')
    
    request.session['request_token'] = auth_props
    return HttpResponseRedirect(auth_props['auth_url'])


def twitter_callback(request, redirect_url=settings.LOGIN_REDIRECT_URL):
    oauth_verifier = request.GET['oauth_verifier']
    
    twitter = Twython(
        app_key = settings.TWITTER_KEY,
        app_secret = settings.TWITTER_SECRET,
        oauth_token = request.session['request_token']['oauth_token'],
        oauth_token_secret = request.session['request_token']['oauth_token_secret'],
    )
    
    try:
    	authorized_tokens = twitter.get_authorized_tokens(oauth_verifier)
    except:
    	return HttpResponseRedirect('/login')
    
    try:
        user = User.objects.get(tw_auth_token= authorized_tokens['user_id'])
        user.backend = 'django.contrib.auth.backends.ModelBackend'

        if user.is_active:
            authenticate(username=user.username, password=user.password)
            login(request, user)
            return HttpResponseRedirect('/dashboard')
        else:
            messages.add_message(request, messages.SUCCESS, 'Your account is not active')
            return HttpResponseRedirect('/')
    except User.DoesNotExist:
    		pass
    return render(request, 'templates/related_information.html', {'tw_auth_token': authorized_tokens['user_id']})


def send_notification(contact_number, mobile_message):
	client = Client(settings.ACCOUNT_SID, settings.AUTH_TOKEN)
	contact_number = settings.CONTACT_NUMBER
	try:
		b = client.messages.create(
		    to = '+44' + contact_number, # user contact number
		    from_ = '+441233800481', # Twilio account no. 
		    # from_ = '+15005550006',
		    body = str(mobile_message),	
		)
	except:
		pass
	

@method_decorator(login_required, name='dispatch')
class ReferFriend(View):
	@cache_control(no_cache=True, must_revalidate=True, no_store=True)
	def get(self,request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')

		group = UserGroup.objects.get(user = request.user.id).name
		if group == "Service Seeker":
			notification = Notification.objects.filter(user=request.user, is_read=False)
			notification_count = notification.count()
			mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
			mssg_count = mssg.count()
			return render(request, 'templates/seeker/invite_user.html', {'group': group,
																	'notifications': notification,
																	'notification_count': notification_count,
																	'mssg': mssg,
																	'mssg_count': mssg_count})
		else:
			return HttpResponseRedirect('/')

	def post(self,request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')

		first_name = request.POST['first_name']
		last_name = request.POST['last_name']
		email = request.POST['email']
		subject = 'Carers Direct : Invitation'
		message_type = "Refer Friend"
		emailid = str(email)
		push_email = EmailMessageNotification(request, subject, message_type, emailid, contract_name=None)
		messages.add_message(request, messages.SUCCESS, 'An email has been sent to your friend.\n Now refer another friend.')
		return HttpResponseRedirect('/dashboard/invite-user')


#@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@login_required
def dashboard(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')

	group = UserGroup.objects.all()
	user_group = UserGroup.objects.get(user = request.user.id).name
	if user_group == "Service Provider" and request.user.profile_complete == 0:
		return HttpResponseRedirect('/provider/complete_profile/')  
	try:
		group = UserGroup.objects.get(user = request.user).name
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.filter(is_read=False).count()
		if group == "Service Seeker":
			return HttpResponseRedirect('/dashboard/find_carer/')
		else:
			return HttpResponseRedirect('/dashboard/contracts/')
	except:
		messages.add_message(request, messages.INFO, 'Please login first')
		return HttpResponseRedirect('/')


def login_view(request):

	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')

	if not request.user.is_anonymous:
		return HttpResponseRedirect("/")
	
	if request.method == "POST":
		username = request.POST['u']
		password = request.POST['p']
		user = authenticate(username=username, password=password)
		try:
			current_user= User.objects.get(username=username)
			loginattemps = LoginFail.objects.filter(user_id=current_user.id).order_by('-added')[0]
			date = loginattemps.added
			now_plus_10 = date + datetime.timedelta(minutes = 1)
			if datetime.datetime.now() > now_plus_10:
				LoginFail.objects.filter(user_id=current_user.id).delete()
		
		except:
			pass
		try:
			loginattemp = LoginFail.objects.filter(user_id=current_user.id).count()
		except:
			loginattemp=0

			
		

		if loginattemp <8: 
			if user is not None:
				try: 
					login(request, user)
					if user.is_superuser:
						return HttpResponseRedirect('/admin/')
					else:
						# changes by pavan sharma
						get_current_url = request.get_full_path()
						if 'next=/' in get_current_url:
							split_url = get_current_url.split("next=/")[1]
							return HttpResponseRedirect("/"+split_url)
						else:
							return HttpResponseRedirect('/dashboard')
				except:
					pass
			else:
				try:
					user = User.objects.get(username=username)
					f = LoginFail(user_id=user.id)
					f.save()

					if user.is_active:
						# changes by pavan
						messages.add_message(request, messages.ERROR, 'Email or password incorrect, please try again.')
					else:
						# changes by pavan
						messages.add_message(request, messages.ERROR, 'Your account is deactivated. Please contact to administrator.')
					return HttpResponseRedirect('/login/')
				except:
					messages.add_message(request, messages.ERROR, 'Email or password incorrect, please try again.')
					return HttpResponseRedirect('/login/')
		else:
			messages.add_message(request, messages.ERROR, 'Please Retry in 60 seconds.')

	secure = "False"
	host = request.get_host()
	redirect_url = "http://"+str(host)+"/dashboard"
	if request.is_secure():
		secure = "True"
		redirect_url = "https://"+str(host)+"/dashboard"
	return render(request, 'templates/login.html', {'redirect_url': redirect_url})


def logout_view(request):
	logout(request)
	return HttpResponseRedirect('/')


# To search all Carers
class SearchView(View):

	def get(self, request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		gender = ""
		caretype = "" 
		q = ""
		check_skill = []
		check_expertise = []
		check_language = []
		Postcode = False
		try:
			b = request.GET['q']
			q = b
			query = """SELECT distinct auth_user.id, auth_user.username FROM auth_user inner join auth_user_groups on auth_user.id = auth_user_groups.user_id inner JOIN carers_app_user_skill ON auth_user.id = carers_app_user_skill.user_id inner JOIN carers_app_user_language ON auth_user.id=carers_app_user_language.user_id inner JOIN carers_app_user_conditionexpertise ON auth_user.id=carers_app_user_conditionexpertise.user_id inner JOIN carers_app_user_caretype ON auth_user.id=carers_app_user_caretype.user_id inner join carers_app_language on carers_app_language.id = carers_app_user_language.language_id inner join carers_app_conditionexpertise on carers_app_conditionexpertise.id = carers_app_user_conditionexpertise.expertise_id inner join carers_app_skill on carers_app_skill.id = carers_app_user_skill.skill_id inner join carers_app_caretype on carers_app_caretype.id =carers_app_user_caretype.caretype_id"""
			if b != "":
				user = User.objects.filter(Q(first_name=str(b))|Q(last_name=str(b)))
				if user.count()==0:
					Postcode = True
					postcode = str(b)
					url = 'https://maps.googleapis.com/maps/api/geocode/json?address='+str(postcode)+', United Kingdom'+'&key=AIzaSyDdJSTee3k9yMmw5gtZnQp0D-v082HNqos'
					r = requests.post(url=url, verify=False)
					if r.status_code == 200:
						import json, pprint
						data = json.loads(r.text)
						b = pprint.PrettyPrinter(indent=2)
						lat_long = data['results'][0]['geometry']['location']
						data = json.dumps(lat_long)
						lat = lat_long['lat']
						lng = lat_long['lng']
						query = "SELECT distinct auth_user.id, auth_user.username, ( 3959 * acos( cos( radians(" + str(lat)+ " ) ) * cos( radians( lat ) ) * cos( radians( lng ) - radians(" +str(lng) + "  ) ) + sin( radians("+ str(lat) + " ) ) * sin( radians( lat ) ) ) ) AS distance FROM auth_user inner join auth_user_groups on auth_user.id = auth_user_groups.user_id inner JOIN carers_app_user_skill ON auth_user.id = carers_app_user_skill.user_id inner JOIN carers_app_user_conditionexpertise ON auth_user.id=carers_app_user_conditionexpertise.user_id inner JOIN carers_app_user_language ON auth_user.id=carers_app_user_language.user_id inner JOIN carers_app_user_caretype ON auth_user.id=carers_app_user_caretype.user_id inner join carers_app_conditionexpertise on carers_app_conditionexpertise.id = carers_app_user_conditionexpertise.expertise_id inner join carers_app_language on carers_app_language.id = carers_app_user_language.language_id inner join carers_app_skill on carers_app_skill.id = carers_app_user_skill.skill_id inner join carers_app_caretype on carers_app_caretype.id =carers_app_user_caretype.caretype_id Where auth_user.publish=1 And auth_user.is_active=1 "
				else:
					query = query+" where auth_user.is_active=1 and auth_user.publish=1 and (auth_user.post_code='{0}' or auth_user.first_name like '%%{1}%%'  or auth_user.last_name like '%%{2}%%'  or carers_app_skill.name='{3}' or carers_app_language.name='{4}' or auth_user.city like '%%{5}%%' or carers_app_conditionexpertise.name='{6}' )".format(str(q),str(q),str(q),str(q),str(q),str(q),str(q))
				
				if 'gender' in request.GET:
					if request.GET['gender']:
						if request.GET['gender'] == 'Male':
							gender = "Male"
							query = query + " and auth_user.gender = 'Male' "
						elif request.GET['gender'] == 'Female':
							gender = "Female"
							query = query + " and auth_user.gender = 'Female' "
				
				if 'caretype' in request.GET:
					caretype = str(request.GET['caretype'])
					if request.GET['caretype'] == 'Hourly':
						caretype = "Hourly"
						care_name = CareType.objects.get(id=1).name
					elif request.GET['caretype'] == 'Over Night':
						caretype = "Over Night"
						care_name = CareType.objects.get(id=2).name
					elif request.GET['caretype'] == 'Live In':
						caretype = "Live In"
						care_name = CareType.objects.get(id=3).name
					query = query + " and carers_app_caretype.name = "+"'"+str(request.GET['caretype'])+"'"
				
				
				skill = []
				language = []
				expertise = []
				for k,vals in request.GET.lists():
					if k == "skill":
						for v in vals:
							if v:
								skill.append(v)
					elif k == "language":
						for v in vals:
							if v:
								language.append(v)
					elif k == "expertise":
						for v in vals:
							if v:
								expertise.append(v)

				
				if len(skill)>0:
					query = query+ " and ("
					for data in skill:
						check_skill.append(data)
						if str(data) == str(skill[-1]):
							query = query+" carers_app_skill.name='%s'"%(str(data))
						else:
							query = query+" carers_app_skill.name='%s' or "%(str(data))
					query = query+ ")"

				if len(language)>0:
					query = query+ " and ("
					for data in language:
						check_language.append(data)
						if data == language[-1]:
							query = query+" carers_app_language.name='%s'"%(str(data))
						else:
							query = query+" carers_app_language.name='%s' or "%(str(data))			
					query = query+ ")"

				if len(expertise)>0:
					query = query+ " and ("
					for data in expertise:
						check_expertise.append(data)
						if data == expertise[-1]:
							query = query+" carers_app_conditionexpertise.name='%s' "%(str(data))
						else:
							query = query+" carers_app_conditionexpertise.name='%s' or "%(str(data))
					query = query+ ")"

				if Postcode:
					query = query + " HAVING distance <25 ORDER BY distance LIMIT 0 , 20"
				provider_list = User.objects.raw(query)
				
				list1 = []
				if Postcode:
					for item in provider_list:
							list1.append({'item':item, 'distance':str(round(item.distance, 2))})
				
				if not Postcode:
					for item in provider_list:
						list1.append({'item':item})
			else:
				skill = []
				language = []
				expertise = []
				query = query+" where auth_user.is_active=1"+" and auth_user.publish=1"
				if 'gender' in request.GET:
					if request.GET['gender']:
						if request.GET['gender'] == 'Male':
							gender = "Male"
							query = query + " and auth_user.gender = 'Male'"
						elif request.GET['gender'] == 'Female':
							gender = "Female"
							query = query + " and auth_user.gender = 'Female'"
				
				if 'caretype' in request.GET:
					if request.GET['caretype']:
						if request.GET['caretype'] == 'Hourly':
							caretype = "Hourly"
							care_name = CareType.objects.get(id=1).name
						elif request.GET['caretype'] == 'Over Night':
							caretype = "Over Night"
							care_name = CareType.objects.get(id=2).name
						elif request.GET['caretype'] == 'Live In':
							caretype = "Live In"
							care_name = CareType.objects.get(id=3).name
						query = query + " and carers_app_caretype.name = "+"'"+str(care_name)+"'"
				
				for k,vals in request.GET.lists():
					if k == "skill":
						for v in vals:
							if v:
								skill.append(v)
					elif k == "language":
						for v in vals:
							if v:
								language.append(v)
					elif k == "expertise":
						for v in vals:
							if v:
								expertise.append(v)

				if len(skill)>0:
					query = query+ " and ("
					for data in skill:
						check_skill.append(data)
						if str(data) == str(skill[-1]):
							query = query+" carers_app_skill.name='%s'"%(str(data))
						else:
							query = query+" carers_app_skill.name='%s' or "%(str(data))
					query = query+ ")"

				if len(language)>0:
					query = query+ " and ("
					for data in language:
						check_language.append(data)
						if data == language[-1]:
							query = query+" carers_app_language.name='%s'"%(str(data))
						else:
							query = query+" carers_app_language.name='%s' or "%(str(data))			
					query = query+ ")"

				if len(expertise)>0:
					query = query+ " and ("
					for data in expertise:
						check_expertise.append(data)
						if data == expertise[-1]:
							query = query+" carers_app_conditionexpertise.name='%s' "%(str(data))
						else:
							query = query+" carers_app_conditionexpertise.name='%s' or "%(str(data))
					query = query+ ")"
				provider_list = User.objects.raw(query)
				list1 = []
				
				for item in provider_list:
					list1.append({'item':item})
		except:
			gender = {}
			caretype = {}
			skill = []
			language = []
			expertise = []
			for k,vals in request.GET.lists():
				if k == "gender":
					for v in vals:
						if v:
							gender['gender'] = str(v)
				elif k == "skill":
					for v in vals:
						if v:
							skill.append(v)
				elif k == "language":
					for v in vals:
						if v:
							language.append(v)
				elif k == "expertise":
					for v in vals:
						if v:
							expertise.append(v)
				elif k == "type":
					for v in vals:
						if v:
							caretype['caretype'] = int(v)

			query = """SELECT distinct auth_user.id, auth_user.username, auth_user_groups.group_id  
			from auth_user 
			inner join auth_user_groups 
			on (auth_user.id = auth_user_groups.user_id) 
			inner join carers_app_user_skill 
			on (auth_user.id = carers_app_user_skill.user_id) 
			inner join carers_app_user_language 
			on (auth_user.id = carers_app_user_language.user_id) 
			inner join carers_app_user_conditionexpertise 
			on (auth_user.id = carers_app_user_conditionexpertise.user_id) 
			inner join carers_app_user_caretype 
			on (auth_user.id = carers_app_user_caretype.user_id) 
			where auth_user_groups.group_id=2 and auth_user.is_active=1 and auth_user.publish=1"""
			
			if len(skill)>0:
				query = query+ " and ("
				for data in skill:
					check_skill.append(data)
					if str(data) == str(skill[-1]):
						query = query+" carers_app_skill.name='%s'"%(str(data))
					else:
						query = query+" carers_app_skill.name='%s' or "%(str(data))
				query = query+ ")"

			if len(language)>0:
				query = query+ " and ("
				for data in language:
					check_language.append(data)
					if data == language[-1]:
						query = query+" carers_app_language.name='%s'"%(str(data))
					else:
						query = query+" carers_app_language.name='%s' or "%(str(data))			
				query = query+ ")"

			if len(expertise)>0:
				query = query+ " and ("
				for data in expertise:
					check_expertise.append(data)
					if data == expertise[-1]:
						query = query+" carers_app_conditionexpertise.name='%s' "%(str(data))
					else:
						query = query+" carers_app_conditionexpertise.name='%s' or "%(str(data))
				query = query+ ")"

			if len(gender)>0:
				query = query+" and auth_user.gender='%s' "%(gender["gender"])

			if len(caretype)>0:
				query = query+' and carers_app_caretype.name=%s'%(caretype['caretype'])
			list1 = []
			provider_list = User.objects.raw(query)
			for item in provider_list:
				list1.append({'item':item})
		count = len(list1)
		paginator = Paginator(list1, 10) 
		page = request.GET.get('page')
		try:
			list1 = paginator.page(page)
		except PageNotAnInteger:
			# If page is not an integer, deliver first page.
			list1 = paginator.page(1)
		except EmptyPage:
			# If page is out of range (e.g. 9999), deliver last page of results.
			list1= paginator.page(paginator.num_pages)
		
		language_list = Language.objects.filter(is_active=True)
		skill_list = Skill.objects.filter(is_active=True)
		expertise_list = ConditionExpertise.objects.filter(is_active=True)
		group = ''
		try:
			group = UserGroup.objects.get(user = request.user).name
		except:
			group = ''
		if '/dashboard/providers/' in request.path and str(request.user) != 'AnonymousUser':
			template_name = 'templates/seeker/search_list.html'
			group = UserGroup.objects.get(user = request.user).name		
			notification = Notification.objects.filter(user=request.user, is_read=False)
			notification_count = notification.count()
			mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
			mssg_count = mssg.count()
			return render(request, template_name, {'list': list1, 'count': count,
												    'notifications': notification,
													'notification_count': notification_count,
													'user': request.user,
													'group': group,
													'Postcode': Postcode,
													'gender': gender,
													'caretype': caretype,
													'language_list': language_list,
													'skill_list': skill_list,
													'expertise_list': expertise_list,
													'mssg': mssg,
													'mssg_count': mssg_count,
													'check_expertise':check_expertise,
													'check_language':check_language,
													'check_skill':check_skill})
		else:
			template_name = 'templates/search_list.html'
			return render(request, template_name, {'list': list1, 
													'count': count,
													'q': q, 
													'gender': gender,
													'caretype': caretype,
													'group':group,
													'Postcode': Postcode,
													'language_list': language_list,
													'skill_list': skill_list,
													'expertise_list': expertise_list,
													'check_expertise':check_expertise,
													'check_language':check_language,
													'check_skill':check_skill})


@method_decorator(login_required, name='dispatch')
class ContractView(View):
	
	def dispatch(self, *args, **kwargs):
		return super(ContractView, self).dispatch(*args, **kwargs)

	@cache_control(no_cache=True, must_revalidate=True, no_store=True)
	def get(self, request, contract_id = None):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')

		group = UserGroup.objects.get(user = request.user.id).name		
		notification = Notification.objects.filter(Q(notification_type="contract")| Q(notification_type="user_payment") , user=request.user, is_read=False)
		user = User.objects.get(username=request.user)
		notification_count = notification.count()
		today_date = datetime.datetime.now().date()
		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		commission = CommissionManagement.objects.get(id=1).commission 
		all_status = tuple(CONTRACT_CHOICES)
		if group == "Service Seeker":
			#import pdb;pdb.set_trace()
			if contract_id:
				all_contracts = Contract.objects.filter(id=contract_id)
			else:	 
				all_contracts = Contract.objects.filter(seeker = request.user).order_by('-added')
			count = all_contracts.count()
			cards = CardType.objects.filter(is_active=True).values('id', 'name')
			contract_filter = 'All'
			try:
				if 'status' in request.GET and request.GET['status'] != "All":
					all_contracts = all_contracts.filter(status__iexact= dict(CONTRACT_CHOICES).get(request.GET['status']))
					count = all_contracts.count()
					contract_filter = dict(CONTRACT_CHOICES).get(request.GET['status'])

				if 'status' in request.GET and request.GET['status'] == "All":
					all_contracts = all_contracts
					count = all_contracts.count()
					contract_filter = dict(CONTRACT_CHOICES).get(request.GET['status'])

				paginator = Paginator(all_contracts, count) # Show 25 contacts per page

				page = request.GET.get('page')
				try:
					all_contracts = paginator.page(page)
				except PageNotAnInteger:
					# If page is not an integer, deliver first page.
					all_contracts = paginator.page(1)
				except EmptyPage:
					# If page is out of range (e.g. 9999), deliver last page of results.
					all_contracts= paginator.page(paginator.num_pages)


				stripe.api_key = SECRET_STRIPE_KEY

				return render(request, 'templates/contracts.html', {
																'all_contracts': all_contracts,
			 													'group': group,
			 													'notification_count': notification_count,
		 														'notifications': notification,
		 														'cards': cards,
		 														'filter': contract_filter,
		 														'count': count,
		 														'today_date': today_date,
		 														'mssg': mssg,
		 														'mssg_count': mssg_count,
		 														'all_status': all_status,
		 														'commission':commission,
		 														})

			except:
				paginator = Paginator(all_contracts, 10) # Show 25 contacts per page

				page = request.GET.get('page')
				try:
					all_contracts = paginator.page(page)
				except PageNotAnInteger:
					# If page is not an integer, deliver first page.
					all_contracts = paginator.page(1)
				except EmptyPage:
					# If page is out of range (e.g. 9999), deliver last page of results.
					all_contracts= paginator.page(paginator.num_pages)
				duties = []
				# for duty in all_contracts:
				# 	duties.append(eval(duty.duties))
				
				return render(request, 'templates/contracts.html', {'all_contracts': all_contracts,
		 													'group': group,
		 													'notification_count': notification_count,
		 													'notifications': notification,
		 													'filter': contract_filter,
		 													'cards': cards,
		 													'duties': duties,
		 													'count': count,
		 													'mssg': mssg,
		 													'mssg_count': mssg_count,
		 													'today_date': today_date,
		 													'all_status': all_status,
		 													'commission':commission,
		 													})
		

		if group == "Service Provider":
			all_contracts = Contract.objects.filter(provider= request.user).order_by('-added')
			count = all_contracts.count()
			contract_filter = 'All'
			stripe_id = User.objects.get(username=request.user).stripe_id
			today = datetime.datetime.today().date()
			try:
				if 'status' in request.GET and request.GET['status'] != "All":
					all_contracts = all_contracts.filter(status__iexact=dict(CONTRACT_CHOICES).get(request.GET['status']))
					count = all_contracts.count()
					contract_filter = dict(CONTRACT_CHOICES).get(request.GET['status'])

				if 'status' in request.GET and request.GET['status'] == "All":
					all_contracts = all_contracts
					count = all_contracts.count()
					contract_filter = dict(CONTRACT_CHOICES).get(request.GET['status'])

				paginator = Paginator(all_contracts, 10) # Show 25 contacts per page

				page = request.GET.get('page')
				try:
					all_contracts = paginator.page(page)
				except PageNotAnInteger:
					# If page is not an integer, deliver first page.
					all_contracts = paginator.page(1)
				except EmptyPage:
					# If page is out of range (e.g. 9999), deliver last page of results.
					all_contracts= paginator.page(paginator.num_pages)
                
				
				return render(request, 'templates/provider/contracts.html', {
																'all_contracts': all_contracts,
			 													'group': group,
			 													'notification_count': notification_count,
		 														'notifications': notification,
		 														'filter': contract_filter,
		 														'count': count,
		 														'today_date': today_date,
		 														'mssg': mssg,
		 														'mssg_count': mssg_count,
		 														'all_status': all_status,
		 														'stripe_id':stripe_id,
		 														'user':user,
		 														# 'dbs_expired':dbs_expired,
		 														# 'insurance_expired':insurance_expired,
		 														# 'dbs_expire_alert':dbs_expire_alert,
		 														# 'insurance_expire_alert':insurance_expire_alert,
		 														# 'dbs_expire_days_left':dbs_expire_days_left,
		 														# 'insurance_expire_days_left':insurance_expire_days_left,
		 														})
			except:
				paginator = Paginator(all_contracts, 10) # Show 25 contacts per page

				page = request.GET.get('page')
				try:
					all_contracts = paginator.page(page)
				except PageNotAnInteger:
					# If page is not an integer, deliver first page.
					all_contracts = paginator.page(1)
				except EmptyPage:
					# If page is out of range (e.g. 9999), deliver last page of results.
					all_contracts= paginator.page(paginator.num_pages)

				return render(request, 'templates/provider/contracts.html', {'all_contracts': all_contracts,
		 													'group': group,
		 													'notification_count': notification_count,
		 													'notifications': notification,
		 													'filter': contract_filter,
		 													'count': count,
		 													'today_date': today_date,
		 													'mssg': mssg,
		 													'mssg_count': mssg_count,
		 													'all_status': all_status,
		 													'stripe_id':stripe_id,
		 													'user':user,
		 													# 'dbs_expire_alert':dbs_expire_alert,
		 													# 'insurance_expire_alert':insurance_expire_alert,
		 													# 'dbs_expire_days_left':dbs_expire_days_left,
		 													# 'insurance_expire_days_left':insurance_expire_days_left,
		 													})


	# Add contract_id =  None in POST method :Pavan Sharma 30/05/2018

	def post(self, request, contract_id = None):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')                                                                                                                                                                                     
		if "Accept" in request.POST:
			today = datetime.date.today()
			try:

				# Check contract status
				if Contract.objects.filter(id = request.POST['contract_id'], status = "Confirmed" ).exists():
					messages.add_message(request, messages.SUCCESS, "Contract Already accepted. Please refresh the page to see the changes")
					return HttpResponseRedirect("/dashboard/contracts")

				# Contract state change to confirmed when accepted
				contract = Contract.objects.get(pk = request.POST['contract_id'])
				contract.status = "Confirmed"
				# Pavan Sharma 28/06/2018

				charge_id = "None"
				# Stripe deposit amount from seeker card equal to contract cost
				try:
					stripe.api_key = settings.SECRET_STRIPE_KEY
					customer = contract.seeker.stripe_id
					amount = float(contract.total_cost)*100  #Convert contract amount into cent
					card_info=(stripe.PaymentMethod.list(
					  customer=customer,
					  type="card",
					))
					payment_id = card_info["data"][0]["id"]
					payout = stripe.PaymentIntent.create(
					  amount=int(amount),
					  currency="gbp",
					  customer=customer,
					  payment_method=payment_id,
					  off_session=True,
				      confirm=True,
				      description="Contract Deposit for : " + contract.name
					)
					payment_intent = stripe.PaymentIntent.retrieve(str(payout["id"]))
					charge_id= payment_intent['charges']['data'][0]['id']
					# Save charge id to contract for future aspect 
 					contract.payment_id = charge_id
 					contract.save()
# 					payout = stripe.Charge.create(
# 						  amount=int(amount),
# 						  currency="gbp",
# 						  customer=customer,
# 						  description=" Contract Deposit for :" + contract.name
# 					)
				except:
					messages.add_message(request, messages.SUCCESS, "Carer seeker card is decline. Please convey the same to him. ")
					return HttpResponseRedirect("/dashboard/contracts")
 				# Save charge id to contract for future aspect 
#  				contract.payment_id =charge_id
#  				contract.save()
				try:
					# Invoice generated in open state
					invoice = Invoices.objects.get(contract=contract)
				except:
					due_date = today+datetime.timedelta(days=7)
					contract_price = float(contract.total_cost)
					half_hour_price = 0
					if contract.service_type == "Fixed" and contract.caretype.name == "Hourly":
						hours = contract.duration.split(',')[0].split(' ')[0]
						contract_price = int(hours)*float(contract.price)
						if contract.duration.split(',')[-1].split(' ')[0] > 0:
							half_hour_price = float(contract.price)/2
						else:
							half_hour_price = 0

					if contract.service_type == "Ongoing" and (contract.caretype.name == "Live In" or contract.caretype.name == "Over Night"):
						contract_price = float(contract.total_cost)
						half_hour_price = 0


					subtotal = contract_price
					invoice = Invoices(description=contract.duties, contract=contract, send_date=today, due_date=due_date, subtotal=subtotal, total=subtotal )
					invoice.save()
					invoice_name = "INV00"+str(invoice.id)
					invoice.name = invoice_name
					invoice.invoice_status = 'Deposit'
					invoice.save()



				# Create payment record for seeker deposit 
				payment = Payment.objects.create(contract=contract, invoice=invoice, mssg="Deposit for contract", user=contract.seeker, stripe_payment_id=charge_id)
				payment.save()

				# add notification
				notification = Notification(notification_type="contract", user=contract.seeker)
				notification.content = "Your contract " + str(contract.name) +" has been accepted by "+ str(request.user.first_name) +' ' +str(request.user.last_name)  
				notification.save()


				notification = Notification(notification_type="Payment", user=contract.seeker)
				notification.content = "Contract " + str(contract.name) +" has been accepted by "+ str(request.user.first_name) +' ' +str(request.user.last_name)  
				notification.save()

				subject = 'Carers Direct : Accept Booking'
				message_type = "Accept Contract"
				email = str(contract.seeker.email)
				contract_name = contract.name
				push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)

				if request.is_secure():
					link='https://'+str(request.get_host())
				else:
					link='http://'+str(request.get_host())

				link = str(link)+"/dashboard/contracts/"
									
				#send mobile notification
				if contract.seeker.telephone_number:
					telephone_number=contract.seeker.telephone_number
					number = telephone_number.replace(" ", "")
					seeker_message = "Dear "+str(contract.seeker.first_name).title()+ " " +str(contract.seeker.last_name).title() +"," +" Your chosen carer "+ str(contract.provider.first_name)+" "+str(contract.provider.last_name) +" has accepted your booking contract "+ str(contract.name) +" and looks forward to working with you. Please click this "+str(link)
					send_notification(number, seeker_message)

				messages.add_message(request, messages.SUCCESS, 'Congratulations on accepting this contract.')
				return HttpResponseRedirect("/dashboard/contracts")
			except stripe.error.CardError as e:
				messages.add_message(request, messages.SUCCESS, "Carer seeker card is decline. Please convey the same to him. ")
				return HttpResponseRedirect("/dashboard/contracts")
		

		if "Payout" in request.POST:
			contract = request.POST['transfer_amount'] # Contract id

			# Pavan Sharma 28/06/2018
			if Contract.objects.filter(status = "Completed", id = contract).exists():
				messages.add_message(request, messages.SUCCESS, 'Contract is already updated. Please refresh the page to see the changes')
				return HttpResponseRedirect('/dashboard/contracts/')	


			group = UserGroup.objects.get(user = request.user.id).name
			contract_obj = Contract.objects.get(pk=contract)
			invoice = Invoice.objects.get(contract=contract_obj)


			# Convert amount into cent
			amount = float(contract_obj.total_cost)*100
			if contract_obj.contract_commission > 0:
				commission = contract_obj.contract_commission
			else:
				commission = CommissionManagement.objects.get(id=1).commission
			#Calculate amount for release payment
			released_amount = (amount*100)/(int(commission)+100.0)

			stripe.api_key = settings.SECRET_STRIPE_KEY
			stripe_account = contract_obj.provider.stripe_id
			transaction_id, stripe_error, stripe_msg = '', '', ''

			try:
				transaction_id = stripe.Transfer.create(
					amount=int(released_amount),
					currency="gbp",
					description="payament transfered for contract : " + contract_obj.name,
					destination=str(stripe_account)
				)

				# stripe_response = stripe.Payout.create(
				# 	amount=int(released_amount),
				# 	currency="gbp",
				# 	stripe_account=str(stripe_account),
				# )

			except Exception,e:
				stripe_msg = e[0]
				stripe_error = 'payout pending'


			# Convert amount cent to actual cost
			released_amount = released_amount / 100
			# Calculate admin commsion

			admincommission = float(contract_obj.total_cost)  - float(released_amount)

			if stripe_error != 'payout pending':
				contract_obj.status = "Completed"
				contract_obj.save()
				invoice.status = dict(STATUS_CHOICES).get('4')
				invoice.save()

				mssg = "Payment for service"
				payment = Payment(contract=contract_obj, invoice=invoice, )
				payment.payment_state = dict(PAYMENT_CHOICES).get('Paid')
				payment.mssg = mssg
				payment.actual_refund = released_amount
				payment.user = request.user
				payment.request_state = "Service Received"
				payment.save()

				mssg = "Payment for service."

				#Check service received or not

				payment = Payment(contract=contract_obj, invoice=invoice, )
				payment.payment_state = dict(PAYMENT_CHOICES).get('Paid')
				payment.mssg = mssg
				payment.actual_refund = released_amount
				payment.user = contract_obj.provider
				payment.request_state = "Service Received"
				payment.save()


				contract_commission = ContractCommission()
				contract_commission.contract = contract_obj
				contract_commission.commission_get = admincommission
				contract_commission.released_amount = released_amount
				contract_commission.save()

				# Send Email
				subject = 'Carers Direct: Service Complete'
				message_type = "Service Complete"
				email = str(contract_obj.provider.email)
				contract_name = str(contract_obj.name)
				push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)

				name = contract_obj.name
				if name == '':
					name = "None"

				content = "Payment recieved for "+ str(name) + " from "+ str(request.user.first_name)+ ' '+ str(request.user.last_name)
				notification = Notification(notification_type="user_payment", content=content, user=contract_obj.provider )
				notification.save()

				content = "Payment recieved for "+ str(name) + " from "+ str(request.user.first_name)+ ' '+ str(request.user.last_name)
				notification = Notification(notification_type="Payment", content=content, user=contract_obj.provider )
				notification.save()

				messages.add_message(request, messages.SUCCESS, 'Thanks for using our service.')
				return HttpResponseRedirect('/dashboard/contracts/')

			else:
				contract_obj.status = "Completed"
				contract_obj.save()
				invoice.status = dict(STATUS_CHOICES).get('1')
				invoice.save()

				mssg = "Payment for service"
				payment = Payment(contract=contract_obj, invoice=invoice, )
				payment.payment_state = dict(PAYMENT_CHOICES).get('Pending')
				payment.mssg = mssg
				payment.user = request.user
				payment.request_state = "Ask For Release"
				payment.save()

				mssg = "Payment for service."


				payment = Payment(contract=contract_obj, invoice=invoice, )
				payment.payment_state = dict(PAYMENT_CHOICES).get('Pending')
				payment.mssg = mssg
				# payment.actual_refund = released_amount
				payment.user = contract_obj.provider
				payment.ask_refund = float(contract_obj.total_cost)
				payment.request_state = "Ask For Release"
				payment.save()

				# contract_commission = ContractCommission()
				# contract_commission.contract = contract_obj
				# contract_commission.commission_get = admincommission
				# contract_commission.released_amount = released_amount
				# contract_commission.save()

				contract_name = str(contract_obj.name)
				name = contract_obj.name
				if name == '':
					name = "None"


				content = "Request for release payment  has been  neglected by stripe.Please have a look into this.Below share message came from stripe."
				content += '</br></br>'+ str(stripe_msg)
				content += '</br></br>'+ '<span style="font-weight: bold;">User name</span>:'+str(request.user.first_name)+ ' '+ str(request.user.last_name)
				content += '</br></br>'+ '<span style="font-weight: bold;">Contract name</span>:'+ str(name)
				# Send email for admin while payout failed and notification


				# If admin user is not in database
				try:
					admin = User.objects.get(is_superuser=True)
					notification = Notification(notification_type="admincontract", content=content, user = admin)
					notification.save()

					msg = EmailMessage('Request For Release Payment', content, to= [admin.email], from_email= settings.EMAIL_HOST_USER)
					msg.content_subtype = "html"
					msg.send()
				except Exception,e:
					print ">>>>>>>>>>>>",e
					pass

				messages.add_message(request, messages.SUCCESS, 'Something went wrong. Please contact Carers Direct.')
				return HttpResponseRedirect('/dashboard/contracts/')

		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()

		if "Help" in request.POST:
			notification = Notification.objects.filter(user=request.user, is_read=False)
			notification_count = notification.count()
			group = UserGroup.objects.get(user = request.user.id).name
			address = request.POST['adddresslocation']
			citylocation = request.POST['citylocation']
			postcode = request.POST['postcode']
			duties = request.POST['duties']
			notes = request.POST['notes']
			address = ''
			contract_id = request.POST['help_contract_id']
			url = 'https://maps.googleapis.com/maps/api/geocode/json?address='+str(postcode)+'&key=AIzaSyDdJSTee3k9yMmw5gtZnQp0D-v082HNqos'
			r = requests.post(url=url, verify=False)
			if r.status_code == 200:
				import json, pprint
				data = json.loads(r.text)
				b = pprint.PrettyPrinter(indent=2)
				lat_long = data['results'][0]['geometry']['location']
				data = json.dumps(lat_long)
				lat = lat_long['lat']
				lng = lat_long['lng']
				query = "SELECT distinct auth_user.id, auth_user.username, ( 3959 * acos( cos( radians(" + str(lat)+ " ) ) * cos( radians( lat ) ) * cos( radians( lng ) - radians(" +str(lng) + "  ) ) + sin( radians("+ str(lat) + " ) ) * sin( radians( lat ) ) ) ) AS distance FROM auth_user inner join auth_user_groups on auth_user.id = auth_user_groups.user_id inner JOIN carers_app_user_skill ON auth_user.id = carers_app_user_skill.user_id inner JOIN carers_app_user_language ON auth_user.id=carers_app_user_language.user_id inner JOIN carers_app_user_caretype ON auth_user.id=carers_app_user_caretype.user_id inner join carers_app_language on carers_app_language.id = carers_app_user_language.language_id inner join carers_app_skill on carers_app_skill.id = carers_app_user_skill.skill_id inner join carers_app_caretype on carers_app_caretype.id =carers_app_user_caretype.caretype_id Where auth_user.publish=1 And auth_user.is_active=1 HAVING distance <25 ORDER BY distance LIMIT 0 , 20"
				list1 = []
				provider_list = User.objects.raw(query)
				for item in provider_list:
					if str(item.email) == str(request.user.email):
						pass
					else:
						list1.append({'item':item, 'distance':str(round(item.distance, 2))})
				return render(request, 'templates/provider/help_list.html', {'group': group,
																			'list': list1,
																			'notification_count': notification_count,
		 																	'notifications': notification,
																			'contract_id': contract_id,
																			'mssg': mssg,
		 																	'mssg_count': mssg_count,
		 																	'duites':duties,
		 																	'notes':notes})


		if "ReleasePayment" in request.POST:
			mssg = request.POST['reason']
			reason_mssg = request.POST['reason_desc']
			contract = request.POST['contract_id']
			contract = Contract.objects.get(id=contract)
			invoice = Invoices.objects.get(contract=contract)
			group = UserGroup.objects.get(user = request.user.id).name

			if contract.status == "Completed":
				messages.add_message(request, messages.SUCCESS, 'Contract is mark done by Service seeker. Your payment will be  credit credited to your bank account soon.')
				return HttpResponseRedirect('/dashboard/contracts/')

			if group == "Service Seeker":

				# Changes by pavan sharma 28/26/2018

				if 	contract.ask_for_refund == True:
					messages.add_message(request, messages.SUCCESS, "Request status has been changed.Please refresh your page.")
					return HttpResponseRedirect('/dashboard/contracts')

				if float(contract.total_cost)<float(request.POST['refund_amount']):
					messages.add_message(request, messages.SUCCESS, "You can't ask for refund more than contract cost.")
					return HttpResponseRedirect('/dashboard/contracts')


				notification_type = "Payment"
				contract.ask_for_refund = True
				contract.cancelled_by = 1
				refund_amount = request.POST['refund_amount']
				status = dict(PAYMENT_CHOICES).get('Pending')
				if Payment.objects.filter(user_id=contract.seeker_id, contract_id=contract.id, request_state ="Ask For Refund").exists() is True:
					paymentseeker = Payment.objects.get(user_id=contract.provider_id,invoice=invoice, contract_id=contract.id, request_state ="Ask For Refund")
					paymentseeker.mssg= mssg
					paymentseeker.invoice= invoice
					paymentseeker.ask_refund= float(refund_amount)
					paymentseeker.payment_state= status
					paymentseeker.ask_refund_note = reason_mssg
					paymentseeker.save()
				else:
					payment = Payment(user=contract.seeker, contract=contract, mssg=mssg, invoice=invoice, request_state="Ask For Refund", ask_refund=float(refund_amount),  payment_state=status)
					payment.save()
				
				content = str(request.user.first_name)+' '+ str(request.user.last_name)+" asked for refund for contract "+ str(contract.name) + " . Reason for refund is: "+ str(mssg)

			if group == "Service Provider":

				# Changes by pavan sharma 28/26/2018
				if 	contract.ask_for_release == True:
					messages.add_message(request, messages.SUCCESS, "Please refresh your page.")
					return HttpResponseRedirect('/dashboard/contracts')

					
				if float(contract.total_cost)<float(request.POST['refund_amount']):
					messages.add_message(request, messages.SUCCESS, "You can't ask for release more than contract cost.")
					return HttpResponseRedirect('/dashboard/contracts')



				notification_type = "Payment"
				contract.ask_for_release = True
				contract.cancelled_by = 2
				released_amount = request.POST['refund_amount']
				
				status = dict(PAYMENT_CHOICES).get('Pending')
				if Payment.objects.filter(user_id=contract.provider_id, contract_id=contract.id, request_state ="Ask For Release").exists() is True:
					paymentprovider = Payment.objects.get(user_id=contract.provider_id,invoice=invoice, contract_id=contract.id, request_state ="Ask For Release")
					paymentprovider.mssg= mssg
					paymentprovider.invoice= invoice
					paymentprovider.ask_refund= float(released_amount)
					paymentprovider.payment_state= status
					paymentprovider.ask_release_note = reason_mssg
					paymentprovider.save()
				else:
					payment = Payment(user=contract.provider, contract=contract, mssg=mssg, invoice=invoice, request_state="Ask For Release", ask_refund=float(released_amount),  payment_state=status)
					payment.save()
				content = str(request.user.first_name)+' '+ str(request.user.last_name)+" asked for release for contract "+ str(contract.name) + ". Reason for release is: "+ str(mssg)


			contract.save()

			messages.add_message(request, messages.SUCCESS, 'Your request has been successfully sent.')
			return HttpResponseRedirect('/dashboard/contracts')


		if "SendHelp" in request.POST:
			contract_id = request.POST['contract_id']
			contract = Contract.objects.get(pk=int(contract_id))
			user_id = request.POST['providers_id']
			duties = request.POST['duties']
			notes = request.POST['notes']
			b = str(user_id)
			provider_list = b.split(',')[: -1]
			email_list = []
			for i in provider_list:
				user = User.objects.get(pk=int(i))
				notification = Notification(user=user ,notification_type="Help")
				notification.content = "Your are invited by "+ str(request.user.first_name) + str(request.user.last_name) + " for help to contract " + str(contract.name)
				notification.save()
				email_list.append(user.email)
				Help = HelpMessage(contract=contract, providers= str(user.first_name +' '+ user.last_name), duties = duties,notes = notes)
				Help.save()
			# admin.site.register(/chat/stream
#     Room,
#     list_display=["id", "title", "staff_only"],
#     list_display_links=["id", "title"],
# )/chat/stream
			for i in email_list:
				subject = 'Carers Direct : Help Request'
				message_type = "Help Request"
				email = str(i)
				contract_name = contract.name
				push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)
			
			return HttpResponse(user_id)

		contract_id = request.POST['contract_id']
		reason = request.POST['reason']
		try:
			contract = Contract.objects.get(pk=int(contract_id))
			contract.reason_for_cancellation = str(reason)
			group = UserGroup.objects.get(user = request.user.id).name
			notification = Notification(notification_type="contract")
			if group == "Service Seeker" and contract.status == "Confirmed":
				contract.status = dict(CONTRACT_CHOICES).get("End Contract")
				contract.cancelled_by = 1
				messages.add_message(request, messages.SUCCESS, 'This Contract Ended Successfully.') 
				notification.user = contract.provider
				notification.content = "Your contract "+ str(contract.name) +" has been ended by "+ str(request.user.first_name)  + ' ' + str(request.user.last_name) +".\n Reason for end contract is : "+str(reason)

				admin_notification = Notification(notification_type="admincontract", user=request.user)
				admin_notification.content = "Contract "+ str(contract.name) +" has been ended by "+ str(request.user.first_name) + ' ' + str(request.user.last_name) +".\n Reason for end contract is : "+str(reason) 
				admin_notification.save()

				subject = 'Carers Direct: End Contract'
				message_type = "End Contract"
				email = str(contract.provider.email)

				if contract.seeker.telephone_number:
					seeker_message = "Your contract "+ str(contract.name) +" has been ended by "+ str(request.user.first_name) + ' ' + str(request.user.last_name) +".\n Reason for end contract is : "+str(reason)
					send_notification(contract.seeker.telephone_number, seeker_message)

			if group == "Service Provider" and contract.status == "Confirmed":
				contract.status = dict(CONTRACT_CHOICES).get("End Contract")
				contract.cancelled_by = 2
				messages.add_message(request, messages.SUCCESS, 'This Contract Ended Successfully.')
				
				notification.user = contract.seeker
				notification.content = "Your contract "+ str(contract.name) +" has been ended by "+ str(request.user.first_name) + ' ' + str(request.user.last_name) +".\n Reason for end contract is : "+str(reason) 

				admin_notification = Notification(notification_type="admincontract", user=request.user)
				admin_notification.content = "Contract "+ str(contract.name) +" has been ended by "+ str(request.user.first_name)  + ' '+ str(request.user.last_name) +".\n Reason for end contract is : "+str(reason) 
				admin_notification.save()

				subject = 'Carers Direct: End Contract'
				message_type = "End Contract"
				email = str(contract.seeker.email)

				if contract.provider.telephone_number:
					provider_message = "Your contract "+ str(contract.name) +" has been ended by "+ str(request.user.first_name) +  ' '+str(request.user.last_name) +".\n Reason for end contract is : "+str(reason) 
					send_notification(contract.provider.telephone_number, provider_message)

			if group == "Service Provider" and contract.status == "Pending":
				contract.status = dict(CONTRACT_CHOICES).get("Rejected")
				contract.cancelled_by = 2
				notification.user = contract.seeker
				messages.add_message(request, messages.SUCCESS, 'This contract has been rejected.')
				
				notification.content = "Your contract "+ str(contract.name) +" has been rejected by "+ str(request.user.first_name)+' '+ str(request.user.last_name) +".\n Reason of rejection is : "+str(reason) 
				
				calendar = CalendarEvent.objects.filter(contract_id=contract)
				calendar.update(is_active=False)

				admin_notification = Notification(notification_type="admincontract", user=request.user)
				admin_notification.content = "Contract "+ str(contract.name) +" has been rejected by "+ str(request.user.first_name) +' ' + str(request.user.last_name) +".\n Reason of rejection is : "+str(reason)
				admin_notification.save()

				subject = 'Carers Direct: Reject Contract'
				message_type = "Reject Contract"
				email = str(contract.seeker.email)

				if contract.seeker.telephone_number:
					telephone_number=contract.seeker.telephone_number
					number = telephone_number.replace(" ", "")
					seeker_message = "Dear," + str(contract.seeker.first_name)+ " "+str(contract.seeker.last_name)+" "+ "Unfortunately your chosen carer is unable to accept the booking "+str(contract.name)+" .The reason is: "+str(reason) 
					send_notification(number, seeker_message)

			contract.save() 
			notification.save()
			
			contract_name = contract.name
			push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)
			
			return HttpResponseRedirect('/dashboard/contracts/')
		except Exception as e:
			messages.add_message(request, messages.SUCCESS, str(e.message))
			return HttpResponseRedirect('/dashboard/contracts/')


@method_decorator(login_required, name='dispatch')		
class SettingView(View):
	@cache_control(no_cache=True, must_revalidate=True, no_store=True)
	def get(self, request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		
		group = UserGroup.objects.get(user = request.user).name
		test_instance = get_object_or_404(User, pk=int(request.user.id))
		form = ProfileForm(instance = request.user)
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.count()
		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		line1 = ''
		line2 = ''
		user_care = []
		caretype = CareType.objects.filter(is_active=True)
		user_caretype = User_CareType.objects.filter(user_id = request.user)
		if user_caretype:
				for i in user_caretype:
					user_care.append(str(i.caretype.name))
		if request.user.street_name:
			line1 = str(request.user.street_name).split('&line2=')[0]
			line2 = str(request.user.street_name).split('&line2=')[-1]
		if group == "Service Seeker":
			cards = CardType.objects.filter(is_active=True).values('id', 'name','image')
			try:
				user_card = UserCard.objects.get(user=request.user)
			except:
				user_card = 0
			setup_intent = stripe.SetupIntent.create()
			client_secret = setup_intent.client_secret
			try:
				user = User.objects.get(username=request.user)
				card_info=(stripe.PaymentMethod.list(
				  customer=user.stripe_id,
				  type="card",
				))
				card_holder_name = card_info["data"][0]["billing_details"]["name"]
				last4_digit = card_info["data"][0]["card"]["last4"]
			except:
				card_holder_name = ""
				last4_digit = ""
			return render(request, 'templates/settings.html', {'form': form,
														 'group': group,
														 'user': request.user,
														 'cards': cards,
														 'notifications': notification,
														 'notification_count': notification_count,
														 # 'alert': alert,
														 'user_card': user_card,
														 'mssg': mssg,
		 												 'mssg_count': mssg_count,
		 												 'line1': line1,
		 												 'line2': line2,
 		 												 'client_secret': client_secret,
 		 												 'setup_intent': setup_intent,
 		 												 'stripe_pk_key':settings.PUBLISHABLE_KEY,
 		 												 "card_holder_name":card_holder_name,
 		 												 "last4_digit":last4_digit,
		 												 })
		elif group == "Service Provider":
			try:
				payment_details = ProviderPaymentDetails.objects.get(user=request.user)
			except:
				payment_details = 0
			# Changes by pavan sharma
			try:
				document = UserDocument.objects.get(user=request.user)
			except:
				document = ""
			# end changes
			#return HttpResponseRedirect('/dashboard/setting/')
			return render(request, 'templates/provider/settings.html', {'group': group,
			 												'user': request.user,
			 												'notifications': notification,
														 	'notification_count': notification_count,
														 	'document': document,
														 	'payment': payment_details,
														 	'mssg': mssg,
		 													'mssg_count': mssg_count,
		 													'caretype':caretype,
		 													'user_care' :user_care,
		 													'user_care1':user_caretype
															})


	def post(self,request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		if "SaveCard" in request.POST:
# 			card_holder_name = request.POST['card_holder_name']
# 			cvv = request.POST['email']
# 			card = request.POST['card']
# 			card_number = request.POST['card_number']
# 			valid_month = request.POST['card_month']
# 			valid_year = request.POST['card_year']		
# 			new_date = str(valid_year)+'-'+str(valid_month)+'-'+str(01)
# 			date = datetime.datetime.strptime(new_date, "%Y-%m-%d").date()s
			stripe.api_key = settings.SECRET_STRIPE_KEY
			payment_id = request.POST['payment_method']
			admin_notification = Notification(notification_type="admincontract", user=request.user)
			if User.objects.get(username=request.user).stripe_id == None or User.objects.get(username=request.user).stripe_id == "":
# 				try:
# 					card_token = stripe.Token.create(
# 					  card={
# 					    "number": str(card_number),
# 					    "exp_month": int(valid_month),
# 					    "exp_year": int(valid_year),
# 					    "cvc": str(cvv)
# 					  },
# 					)
# 				except stripe.error.CardError as e:
# 					messages.add_message(request, messages.SUCCESS, str(e.message))
# 					return HttpResponseRedirect('/dashboard/setting/')
				try:
					customer = stripe.Customer.create(
					    email=str(request.user.email),
					    payment_method=payment_id
# 					    source= card_token
					)
					customer_id = customer['id']
					user = User.objects.get(username=request.user)
					user.stripe_id = customer_id
					user.payment_id = payment_id
					user.save()
					messages.add_message(request, messages.SUCCESS, "Your card information saved safely.")
	  				admin_notification.content = "Bank Details for " + str(
	  					request.user.first_name) + " has been updated successfully"
  					admin_notification.save()
				except stripe.error.CardError as e:
					messages.add_message(request, messages.SUCCESS, str(e.message))
					return HttpResponseRedirect('/dashboard/setting/')
			else:
				# Changes made by pavan sharma 27/05/2018
				try:
					user = User.objects.get(username=request.user)
					customer_id = user.stripe_id
  					fingerprint_exists_lst=[]
  					payment_list = stripe.PaymentMethod.list(customer=customer_id, type='card')
					for method in payment_list:
						existing_payment_id = method['card']['fingerprint']
						fingerprint_exists_lst.append(existing_payment_id)
	   				method_fingerprint = stripe.PaymentMethod.retrieve(str(payment_id))['card']['fingerprint']
					if method_fingerprint in fingerprint_exists_lst:
						messages.add_message(request, messages.SUCCESS, "This card is already added.")
					else:
						payment_method = stripe.PaymentMethod.attach(
	 	       														payment_id,
	 	       														customer=customer_id
	        														)
	  	   				user.payment_id = payment_id
	# 					customer = stripe.Customer.create(
	# 					    email=str(request.user.email),s
	# # 					    source= card_token
	# 					)
						user.stripe_id = customer_id
						user.save()
						messages.add_message(request, messages.SUCCESS, "Your card information saved safely.")
		  				admin_notification.content = "Bank Details for " + str(
		  					request.user.first_name) + " has been updated successfully"
	  					admin_notification.save()
				except stripe.error.CardError as e:
					messages.add_message(request, messages.SUCCESS, str(e.message))
					return HttpResponseRedirect('/dashboard/setting/')
				
# 				try:
# 					user_card = UserCard.objects.get(user=request.user)
# 					user_card_number = decrypt_val(str(user_card.card_number))
# 				except:
# 					user_card_number = str(card_number)
# 				if str(user_card_number) != card_number:
#  					try:
#  						card_token = stripe.Token.create(
#  						  card={
#  						    "number": str(card_number),
#  						    "exp_month": int(valid_month),
#  						    "exp_year": int(valid_year),
#  						    "cvc": str(cvv)
#  						  },
#  						)
#  					except stripe.error.CardError as e:
#  						messages.add_message(request, messages.SUCCESS, str(e.message))
#  						return HttpResponseRedirect('/dashboard/setting/')
# 					try:
# 						user = User.objects.get(username=request.user)
# 						customer_id = user.stripe_id
# 						customer = stripe.Customer.create(
# 						    email=str(request.user.email),
# 						    source= card_token
# 						)
# 						user.stripe_id = customer_id
# 						user.save()
# 					except stripe.error.CardError as e:
# 						messages.add_message(request, messages.SUCCESS, str(e.message))
# 						return HttpResponseRedirect('/dashboard/setting/')

#  			card = CardType.objects.get(id=card)
#  			admin_notification = Notification(notification_type="admincontract", user=request.user)
#  			try:
#  				user_card = UserCard.objects.get(user=request.user)
#  				user_card.card_holder_name = card_holder_name
#  				user_card.cardtype = card
#  				user_card.cvv_number = encrypt_val(str(cvv))
#  				user_card.valid_date= date
#  				user_card.card_number = encrypt_val(str(card_number))
#  				user_card.save()
#  				messages.add_message(request, messages.INFO, "Your card information saved safely.")
#  
#  				admin_notification.content = "Bank Details for " + str(request.user.first_name) + " has been updated successfully"
#  				admin_notification.save()
#  
#  			except:
#  				user = User.objects.get(username=request.user)
#  				user_card = UserCard(card_holder_name=card_holder_name, cvv_number=encrypt_val(str(cvv)), email=request.user.email, user=user, cardtype=card, card_number=encrypt_val(str(card_number)), valid_date=date, is_active=True)
#  				user_card.save()
#  				messages.add_message(request, messages.SUCCESS, "Your card information saved safely.")
#  
#  				admin_notification.content = "Bank Details for " + str(
#  					request.user.first_name) + " has been updated successfully"
#  				admin_notification.save()

			return HttpResponseRedirect('/dashboard/setting/')

		elif "ProfileInfo" in request.POST:
			request.POST = request.POST.copy()
			request.POST['contact_number'] = request.POST['contact_number'].replace(" ", "")
			request.POST['telephone_number'] = request.POST['telephone_number'].replace(" ", "")
			form = ProfileForm(request.POST, request.FILES)
			if form.is_valid():
				user = User.objects.get(username=request.user)
				user.first_name = str(form.cleaned_data['first_name']).title()
				user.last_name = str(form.cleaned_data['last_name']).title()
				user.contact_number = form.cleaned_data['contact_number']
				user.telephone_number = form.cleaned_data['telephone_number']
				# user.email = form.cleaned_data['email']
				user.save()
				messages.add_message(request, messages.SUCCESS, "Your profile information changed successfully.")
			else:
				messages.add_message(request, messages.INFO, 'Some error occured.')
			return HttpResponseRedirect('/dashboard/setting/')

		elif "Provider_Info" in request.POST:
			user = User.objects.get(username=request.user)
			if request.FILES.get('profile_pic', False):
				user.image = request.FILES['profile_pic']
				user.save()
			b =  request.POST['dob']
			# Changes by pavan sharma(telephone and contact number)
			contact_number = request.POST['contact_number'].replace(" ", "")
			telephone_number = request.POST['telephone_number'].replace(" ", "")
			if len(b)>0:
				dob = datetime.datetime.strptime(str(request.POST['dob']), "%d-%m-%Y").date() 
				user.dob = dob
				user.contact_number = contact_number
				user.telephone_number = telephone_number	
				user.first_name = str(request.POST['first_name']).title()
				user.last_name = str(request.POST['last_name']).title()
				user.save()			
			messages.add_message(request, messages.SUCCESS, "Your profile information changed successfully.")
			return HttpResponseRedirect('/dashboard/setting/')

		elif "care_type_details" in request.POST:
			code_break = False
			User_CareType.objects.filter(user_id=request.user).delete()
			user = User.objects.get(username=request.user)
			for care in dict(request.POST)['caretype']:
				care_id = CareType.objects.get(pk=int(care))
				get_id = str(care_id.id)
				if float(request.POST['price'+str(get_id)])>float(9999.99):
					code_break = True
					messages.add_message(request, messages.INFO, 'Max value for price is 9999.99 ')
					return HttpResponseRedirect('/dashboard/setting/')
				if code_break == True:
					break
				get_price_id = request.POST['price'+str(get_id)]
				user_care_obj = User_CareType(user=user, caretype= care_id, price = get_price_id )
				user_care_obj.save()
			messages.add_message(request, messages.INFO, 'Care type has been updated successfully.')
			return HttpResponseRedirect('/dashboard/setting/')

		elif "Provider_address" in request.POST:
			user = User.objects.get(username=request.user)
			user.street_name = request.POST['address'] 
			user.city = request.POST['city'] 
			user.country =  request.POST['country']
			user.house_no =  request.POST['town'] 
			user.post_code = request.POST['post_code']
			user.lat = request.POST['lat']
			user.lng = request.POST['long']
			user.save()
			messages.add_message(request, messages.INFO, 'Your address has been updated successfully.')
			return HttpResponseRedirect('/dashboard/setting/')

		elif "ChangePassword" in request.POST:
			old_password = request.POST['old_password']
			valid = check_password(old_password, request.user.password)
			if valid:
				password = request.POST['new_password']
				user = User.objects.get(username=str(request.user))
				user.set_password(password)
				user.save()
				update_session_auth_hash(request, user)
				messages.add_message(request, messages.SUCCESS, 'Your password changed successfully.')
			else:
				messages.add_message(request, messages.INFO, 'Current password is wrong')
			return HttpResponseRedirect('/dashboard/setting/')

		elif "SeekerAddress" in request.POST:
			address = request.POST['seeker_address']
			line1 = request.POST['seeker_line1']
			line2 = request.POST['seeker_line2']
			city = request.POST['seeker_city']
			county = request.POST['seeker_county']
			post_code = request.POST['seeker_post_code']
			
			user = User.objects.get(username=request.user)
			user.house_no = address
			user.street_name = str(line1)+'&line2='+str(line2)
			user.city = city
			user.country = county
			user.post_code = post_code
			user.save()

			messages.add_message(request, messages.SUCCESS, 'Your address saved successfully.')			
			return HttpResponseRedirect('/dashboard/setting/')

		elif "SeekerNotification" in request.POST:
			try:
				message_email = request.POST['message_email1']
				message_email = 1
			except:
				if 'message_email2' in request.POST:
					message_email = 1
				else:
					message_email = 0

			try:
				message_system = request.POST['message_system1']
				message_system = 1
			except:
				if 'message_system2' in request.POST:
					message_system = 1
				else:
					message_system = 0

			try:
				contract_email = request.POST['contract_email1']
				contract_email = 1
			except:
				if 'contract_email2' in request.POST:
					contract_email = 1
				else:
					contract_email = 0

			try:
				contract_system = request.POST['contract_system1']
				contract_system = 1
			except:
				if 'contract_system2' in request.POST:
					contract_system = 1
				else:
					contract_system = 0

			try:
				invoice_email = request.POST['invoice_email1']
				invoice_email = 1
			except:
				if 'invoice_email2' in request.POST:
					invoice_email = 1
				else:
					invoice_email = 0

			try:
				invoice_system = request.POST['invoice_system1']
				invoice_system = 1
			except:
				if 'invoice_system2' in request.POST:
					invoice_system = 1
				else:
					invoice_system = 0

			alert = UserAlert.objects.get(user=request.user)
			alert.message_email_alert = message_email
			alert.message_system_alert = message_system
			alert.contract_email_alert = contract_email
			alert.contract_system_alert = contract_system
			alert.invoice_email_alert = invoice_email
			alert.invoice_system_alert = invoice_system
			alert.save()
			messages.add_message(request, messages.SUCCESS, "Notifications Changed Successfully")
			return HttpResponseRedirect('/dashboard/setting/')
		

		elif "ProviderNotification" in request.POST:
			try:
				message_email = request.POST['message_email1']
				message_email = 1
			except:
				if 'message_email2' in request.POST:
					message_email = 1
				else:
					message_email = 0

			try:
				message_system = request.POST['message_system1']
				message_system = 1
			except:
				if 'message_system2' in request.POST:
					message_system = 1
				else:
					message_system = 0

			try:
				contract_email = request.POST['contract_email1']
				contract_email = 1
			except:
				if 'contract_email2' in request.POST:
					contract_email = 1
				else:
					contract_email = 0

			try:
				contract_system = request.POST['contract_system1']
				contract_system = 1
			except:
				if 'contract_system2' in request.POST:
					contract_system = 1
				else:
					contract_system = 0

			try:
				payment_email = request.POST['payment_email1']
				payment_email = 1
			except:
				if 'payment_email2' in request.POST:
					payment_email = 1
				else:
					payment_email = 0

			try:
				payment_system = request.POST['payment_system1']
				payment_system = 1
			except:
				if 'payment_system2' in request.POST:
					payment_system = 1
				else:
					payment_system = 0

			try:
				help_email = request.POST['help_email1']
				help_email = 1
			except:
				if 'help_email2' in request.POST:
					help_email = 1
				else:
					help_email = 0
			try:
				help_system = request.POST['help_system1']
				help_system = 1
			except:
				if 'help_system2' in request.POST:
					help_system = 1
				else:
					help_system = 0

			alert = UserAlert.objects.get(user=request.user)
			alert.message_email_alert = message_email
			alert.message_system_alert = message_system
			alert.contract_email_alert = contract_email
			alert.contract_system_alert = contract_system
			alert.payment_email_alert = payment_email
			alert.payment_system_alert = payment_system
			alert.help_email_alert = help_email
			alert.help_system_alert = help_system
			alert.save()
			messages.add_message(request, messages.SUCCESS, "Notifications Changed Successfully")
			return HttpResponseRedirect('/dashboard/setting/')

		elif "EmailNotification" in request.POST:
			notification = request.POST['EmailNotification']
			if str(notification) == 'email_disable': 
				user = User.objects.get(username = request.user)
				user.email_alert = False
				user.save()
				data = 'Successfully Disable Email Notifications'
				return HttpResponse(data)

			elif str(notification) == 'email_enable':
				user = User.objects.get(username = request.user)
				user.email_alert = True
				user.save()
				data = 'Successfully Enable Email Notifications'
				return HttpResponse(data)


		elif "SmsNotification" in request.POST:
			notification = request.POST['SmsNotification']
			if str(notification) == 'sms_disable': 
				user = User.objects.get(username = request.user)
				user.sms_alert = False
				user.save()
				data = 'Successfully Disable SMS Notifications'
				return HttpResponse(data)

			elif str(notification) == 'sms_enable':
				user = User.objects.get(username = request.user)
				user.sms_alert = True
				user.save()
				data = 'Successfully Enable SMS Notifications'
				return HttpResponse(data)


		elif "Deactivate" in request.POST:
			user = User.objects.get(username=request.user)
			user.is_active = False
			user.save()
			logout_view(request)
			messages.add_message(request, messages.SUCCESS, 'Your account has been deactivated successfully')
			return HttpResponseRedirect('/')


		elif "Uploaddoc" in request.POST:
			user = User.objects.get(username=request.user)
			user_document = UserDocument.objects.get(user=request.user)
			if request.FILES.get('bank-society-statement-file', False):
				user_document.bank_society_statement = request.FILES['bank-society-statement-file']
				user_document.save()
			
			if request.FILES.get('utility-file', False):
				user_document.utility=request.FILES['utility-file']
				user_document.save()
			
			if request.FILES.get('driving-license-file', False):
				user_document.driving_license = request.FILES['driving-license-file']
				user_document.save()
			
			if request.FILES.get('passport-photo-file', False):
				user_document.passport_photo=request.FILES['passport-photo-file']
				user_document.save()
			
			if request.FILES.get('dbs-file', False):
				user_document.dbs=request.FILES['dbs-file']
				user_document.save()
				
				admin = User.objects.filter(is_superuser=True)
				for i in admin:
					if i.telephone_number:
						telephone_number = i.telephone_number
						number = telephone_number.replace(" ", "")
						message = "Dear admin, provider "+str(user.first_name).title()+ " " +str(user.last_name).title() +" update his/her dbs document. Please verify & update expiry date." 
						send_notification(number, message)

					subject = 'Carers Direct : Update Dbs'
					message_type = 'Admin Update Dbs'
					email = i.email
					contract_name = str(user.first_name) + ' '+str(user.last_name)
					push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)
			
			if request.FILES.get('insurance-file', False):
				user_document.insurance = request.FILES['insurance-file']
				user_document.save()

				admin = User.objects.filter(is_superuser=True)
				for i in admin:
					if i.telephone_number:
						telephone_number = i.telephone_number
						number = telephone_number.replace(" ", "")
						message = "Dear admin, provider "+str(user.first_name).title()+ " " +str(user.last_name).title() +" update his/her insurance document. Please verify & update expiry date." 
						send_notification(number, message)

					subject = 'Carers Direct : Update Insurance'
					message_type = 'Admin Update Insurance'
					email = i.email
					contract_name = str(user.first_name) + ' '+str(user.last_name)
					push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)


			if request.FILES.get('reference1', False):
				user_document.reference1=request.FILES['reference1']
				user_document.save()

			if request.FILES.get('reference2', False):
				user_document.reference2=request.FILES['reference2']
				user_document.save()

			messages.add_message(request, messages.SUCCESS, 'Your document saved successfully')
			return HttpResponseRedirect('/dashboard/setting/')


		elif "Payment_Details" in request.POST:
			bank_name = request.POST['bank_name']
			try:
				account_holder = request.POST['name']
			except:
				account_holder= ""
			account_number = request.POST['account_number']
			sort_code = request.POST['sort_code']
			post_code = request.POST['post_code']
			try:
				doc = UserDocument.objects.get(user=request.user).driving_license
				path = doc.path
			except:
				messages.add_message(request, messages.INFO, "Try uploading driving license file with one of the following mimetypes: image/jpeg, image/png")
				return HttpResponseRedirect('/dashboard/setting/')
			name = str(account_holder).split(' ')
			stripe_id = request.user.stripe_id
			if stripe_id == None or stripe_id == "":
				individual_info = {
				"first_name":str(name[0])
				}
				account = stripe.Account.create(
					country="GB",
					type="custom",
					requested_capabilities=['transfers'],
					email= str(request.user.email),
					stripe_version="2020-03-02",
				 	business_type = "individual",
				 	individual =individual_info,
				)
				stripe_id = account['id']
				try:
					with open(str(path), "r") as fp:
						stripe_file_id = stripe.FileUpload.create(
						purpose="identity_document",
						file=fp
					)
				except Exception as e:
					account = stripe.Account.retrieve(str(stripe_id))
					account.delete()
					messages.add_message(request, messages.INFO, "Try uploading driving license file with one of the following mimetypes: image/jpeg, image/png")
					return HttpResponseRedirect('/dashboard/setting/')
				try:
					import time
					account = stripe.Account.retrieve(str(stripe_id))
					account.business_profile.url = "https://www.carersdirect.org"
					account.individual.last_name = str(name[-1])
					account.individual.dob.day = str(request.user.dob.day)
					account.individual.dob.month = str(request.user.dob.month)
					account.individual.dob.year = str(request.user.dob.year)
					account.individual.address.city = str(request.user.city)
					account.individual.address.line1 = str(request.user.street_name)
					account.individual.address.postal_code = str(post_code)
					account.individual.verification.document.front = stripe_file_id['id']
					account.individual.verification.additional_document.front = stripe_file_id['id']
					account.tos_acceptance.date = int(time.time())
					account.tos_acceptance.ip = settings.HOST_NAME
					bank_detail = {
						"object" : 'bank_account',
						"account_number" : str(account_number),
						"country" : "GB",
						"currency" : "gbp",
						"routing_number" : str(sort_code)
						}

				except stripe.error.InvalidRequestError as e:

					account = stripe.Account.retrieve(str(stripe_id))
					account.delete()
					
					messages.add_message(request, messages.INFO, str(e.message))
					return HttpResponseRedirect('/dashboard/setting/')

				try:
				
					account.external_accounts.create(external_account=bank_detail)
					# account.payout_schedule['interval'] = "daily"
					
					account.save()
				
				except stripe.error.InvalidRequestError as e:
					account = stripe.Account.retrieve(str(stripe_id))
					account.delete()
					messages.add_message(request, messages.INFO, str(e.message))
					return HttpResponseRedirect('/dashboard/setting/')

				user = User.objects.get(username=request.user)
				user.stripe_id = stripe_id
				user.save()
			else:
				try:
					account = stripe.Account.retrieve(str(stripe_id))
					account.individual.first_name = str(name[0])
					account.individual.last_name = str(name[-1])
					account.individual.dob.day = str(request.user.dob.day)
					account.individual.dob.month = str(request.user.dob.month)
					account.individual.dob.year = str(request.user.dob.year)
					account.individual.address.city = str(request.user.city)
					account.individual.address.line1 = str(request.user.street_name)
					account.individual.address.postal_code = str(post_code)
					bank_detail = {
						"object" : 'bank_account',
						"account_number" : str(account_number),
						"country" : "GB",
						"currency" : "GBP",

						}
				except Exception as e:
					messages.add_message(request, messages.INFO, str(e.message))
					return HttpResponseRedirect('/dashboard/setting/')
			admin_notification = Notification(notification_type="admincontract", user=request.user)
			try:
				b = ProviderPaymentDetails.objects.get(user=request.user)
				b.account_number =  encrypt_val(str(account_number))
				b.bank_name = bank_name
				b.account_holder_name = account_holder
				b.sort_code =  encrypt_val(str(sort_code))
				b.state = request.user.city
				b.city = request.user.city
				b.post_code = post_code
				b.save()
				messages.add_message(request, messages.INFO, "Bank details updated successfully.")
				admin_notification.content = "Bank Details for " + str(
					request.user.first_name) + " has been updated successfully"
				admin_notification.save()
			except:
				payment_obj = ProviderPaymentDetails(user=request.user, bank_name=str(bank_name),
				 account_holder_name=account_holder, account_number=encrypt_val(str(account_number)), sort_code=encrypt_val(str(sort_code)), state=request.user.city,
				 city=request.user.city, post_code=post_code)
				payment_obj.save()
				messages.add_message(request, messages.SUCCESS, "Bank details saved successfully.")
				admin_notification.content = "Bank Details for " + str(
					request.user.first_name) + " has been updated successfully"
				admin_notification.save()
			return HttpResponseRedirect('/dashboard/setting/')


class BillingView(LoginRequiredMixin, View):
	login_url = '/login/?next=/dashboard/billing/'
	@cache_control(no_cache=True, must_revalidate=True, no_store=True)
	def get(self, request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')

		group = UserGroup.objects.get(user = request.user).name
		user = User.objects.get(username=request.user)
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.count()
		all_status = STATUS_CHOICES
		cards = CardType.objects.filter(is_active=True)
		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		if group == "Service Seeker":
			if request.path != '/dashboard/payment/':
				billings = Invoices.objects.filter(contract__seeker=user).order_by('-id')
				all_status = tuple(STATUS_CHOICES)
				try:
					if 'status' in request.GET and request.GET['status'] != "0":
						billings = billings.filter(status=dict(STATUS_CHOICES).get(request.GET['status'])).order_by('-send_date')
					
					if 'status' in request.GET and request.GET['status'] == "0":
						billings = billings
					billing_count = billings.count()
					paginator = Paginator(billings, 10) # Show 25 contacts per page

					page = request.GET.get('page')
					try:
						billings = paginator.page(page)
					except PageNotAnInteger:
						# If page is not an integer, deliver first page.
						billings = paginator.page(1)
					except EmptyPage:
						# If page is out of range (e.g. 9999), deliver last page of results.
						billings= paginator.page(paginator.num_pages)
					return render(request, 'templates/seeker/billing.html', {
																 'group': group,
																 'user': user,
																 'billings': billings,
																 'cards': cards,
																 'notifications': notification,
																 'notification_count': notification_count,
																 'billing_count': billing_count,
																 'all_status': all_status,
																 'filter': request.GET['status'] if 'status' in request.GET else 0,
																 'mssg': mssg,
			 													 'mssg_count': mssg_count, 
																 })
				except:
 					billing_count = billings.count()
					paginator = Paginator(billings, 10) # Show 25 contacts per page

					page = request.GET.get('page')
					try:
						billings = paginator.page(page)
					except PageNotAnInteger:
						# If page is not an integer, deliver first page.
						billings = paginator.page(1)
					except EmptyPage:
						# If page is out of range (e.g. 9999), deliver last page of results.
						billings= paginator.page(paginator.num_pages)
					return render(request, 'templates/seeker/billing.html', {
																 'group': group,
																 'user': user,
																 'billings': billings,
																 'cards': cards,
																 'notifications': notification,
																 'notification_count': notification_count,
 																 'billing_count': billing_count,
																 'all_status': all_status,
																 'mssg': mssg,
																 'filter': 0,
			 													 'mssg_count': mssg_count, 
																 })
			else:
				return HttpResponseRedirect('/')

		if group == "Service Provider":
			if request.path != '/dashboard/billing/':
				billings = Payment.objects.filter(user=user).order_by('-added')




				all_status = tuple(PAYMENT_CHOICES)
				try:

					if 'status' in request.GET and (str(request.GET['status']) == "" or str(request.GET['status']) == "All"):
						billings = billings
					elif 'status' in request.GET and request.GET['status'] != "All":
						billings = billings.filter(payment_state=dict(PAYMENT_CHOICES).get(request.GET['status'])).order_by('-added')

					billing_count = billings.count()
					paginator = Paginator(billings, 10) # Show 25 contacts per page

					
					page = request.GET.get('page')
					try:
						billings = paginator.page(page)
					except PageNotAnInteger:
						# If page is not an integer, deliver first page.
						billings = paginator.page(1)
					except EmptyPage:
						# If page is out of range (e.g. 9999), deliver last page of results.
						billings= paginator.page(paginator.num_pages)
					return render(request, 'templates/provider/payment.html', {
																 'group': group,
																 'user': user,
																 'billings': billings,
																 'cards': cards,
																 'notifications': notification,
																 'notification_count': notification_count,
																 'billing_count': billing_count,
																 'all_status': all_status,
																 'filter': request.GET['status'] if 'status' in request.GET else 'All',
																 'mssg': mssg,
			 													 'mssg_count': mssg_count, 
																 })
				except:
					billing_count = billings.count()
					
					paginator = Paginator(billings, 10) # Show 25 contacts per page

					page = request.GET.get('page')
					try:
						billings = paginator.page(page)
					except PageNotAnInteger:
						# If page is not an integer, deliver first page.
						billings = paginator.page(1)
					except EmptyPage:
						# If page is out of range (e.g. 9999), deliver last page of results.
						billings= paginator.page(paginator.num_pages)

					return render(request, 'templates/provider/payment.html', {
																 'group': group,
																 'user': user,
																 'billings': billings,
																 'notifications': notification,
																 'notification_count': notification_count,
																 'billing_count': billing_count,
																 'all_status': all_status,
																 'mssg': mssg,
			 													 'mssg_count': mssg_count,
			 													 'filter': request.GET['status'] if 'status' in request.GET else 'All',
																 })
			else:
				return HttpResponseRedirect('/')


@login_required
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def SeekerPayment(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')

	group = UserGroup.objects.get(user = request.user).name
	user = User.objects.get(username=request.user)
	notification = Notification.objects.filter(user=request.user, is_read=False)
	notification_count = notification.count()
	all_status = PAYMENT_CHOICES
	cards = CardType.objects.filter(is_active=True)
	mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
	mssg_count = mssg.count()

	if group == "Service Seeker":
		billings = Payment.objects.filter(user=user).order_by('-added')
		all_status = tuple(PAYMENT_CHOICES)
		try:
			if 'status' in request.GET and request.GET['status'] != "All":
				billings = billings.filter(payment_state=dict(PAYMENT_CHOICES).get(request.GET['status'])).order_by('-added')
			
			if 'status' in request.GET and request.GET['status'] == "All":
				billings = billings
			
			billing_count = billings.count()
			paginator = Paginator(billings, 10) # Show 25 contacts per page

			page = request.GET.get('page')
			try:
				billings = paginator.page(page)
			except PageNotAnInteger:
				# If page is not an integer, deliver first page.
				billings = paginator.page(1)
			except EmptyPage:
				# If page is out of range (e.g. 9999), deliver last page of results.
				billings= paginator.page(paginator.num_pages)
			return render(request, 'templates/seeker/seekerpayment.html', {
														 'group': group,
														 'user': user,
														 'billings': billings,
														 'cards': cards,
														 'notifications': notification,
														 'notification_count': notification_count,
														 'billing_count': billing_count,
														 'all_status': all_status,
														 'filter': request.GET['status'] if 'status' in request.GET else 'All',
														 'mssg': mssg,
														 
	 													 'mssg_count': mssg_count, 
														 })

		except:
			billing_count = billings.count()
			paginator = Paginator(billings, 10) # Show 25 contacts per page

			page = request.GET.get('page')
			try:
				billings = paginator.page(page)
			except PageNotAnInteger:
				# If page is not an integer, deliver first page.
				billings = paginator.page(1)
			except EmptyPage:
				# If page is out of range (e.g. 9999), deliver last page of results.
				billings= paginator.page(paginator.num_pages)
			return render(request, 'templates/seeker/billing.html', {
														 'group': group,
														 'user': user,
														 'billings': billings,
														 'cards': cards,
														 'notifications': notification,
														 'notification_count': notification_count,
														 'billing_count': billing_count,
														 'all_status': all_status,
														 'mssg': mssg,
														 'filter':'All',
	 													 'mssg_count': mssg_count, 
														 })
	else:
		return HttpResponse('/')


class FindCarer(LoginRequiredMixin, View):
	login_url = '/login/?next=/dashboard/find_carer/'
	# @cache_control(no_cache=True, must_revalidate=True, no_store=True)
	def get(self, request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.count() 
		skill_list = Skill.objects.filter(is_active=True)
		language_list = Language.objects.filter(is_active=True)
		expertise_list = ConditionExpertise.objects.filter(is_active=True) 
		group = UserGroup.objects.get(user = request.user).name
		providers = User.objects.filter(groups__name="Service Provider", is_active=True, publish=True)
		
		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		return render(request, 'templates/seeker/providers.html', {
														 'group': group,
														 'user': request.user,
														 'providers': providers,
														 'language_list': language_list,
														 'expertise_list': expertise_list,
														 'skill_list': skill_list,
														 'notifications': notification,
														 'notification_count': notification_count,
														 'mssg': mssg,
		 												 'mssg_count': mssg_count,
														 })

@login_required
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def provider_profile(request, id):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')

	user = request.user.is_anonymous()
	group = "None"
	try:
		provider = User.objects.get(pk=id, groups__name="Service Provider")
		expertise_list = User_ConditionExpertise.objects.filter(user=id)
		skill_list = User_Skill.objects.filter(user=id)
		user_interest = User_interest.objects.filter(user = id)
		group=UserGroup.objects.get(user = request.user).name
		notification = Notification.objects.filter(user=request.user, is_read=False)
		user_qualification = userqualification.objects.filter(user = id)
		notification_count = notification.count()
		price = User_CareType.objects.filter(user=provider)
		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		languages = User_Language.objects.filter(user=provider)
# 		user_card = UserCard.objects.get(user=request.user)
 		customer_id = User.objects.get(username=request.user).stripe_id
 		payment_id = User.objects.get(username=request.user).payment_id
# 		user_card = "Yes"
	except:
		mssg = []
		mssg_count = 0
		price = 0
# 		user_card = "No"
	if customer_id==None:
		customer_id = "No"
	else:
		customer_id = "Yes"
 	if payment_id==None:
 		payment_id = "No"
 	else:
 		payment_id = "Yes"
	if group == "Service Seeker":
		return render(request, 'templates/seeker/provider_detail.html', {'provider': provider,
															  'expertise_list': expertise_list,
															  'skill_list': skill_list,
															  'price': price,
															  'user': user,
															  'group': group,
															  'notifications': notification,
															  'notification_count': notification_count,
# 															  'user_card': user_card,
 															  'customer_id':customer_id,
 															  'payment_id':payment_id,
															  'mssg': mssg,
															  'language_list': languages,
															  'mssg_count': mssg_count,
															  'interest':user_interest,
															  'user_qualification':user_qualification
															  })
	else:
		return HttpResponseRedirect('/')


class MakeContractView(LoginRequiredMixin, View):
	login_url = '/login/?next=/dashboard/make_contract/'

	@cache_control(no_cache=True, must_revalidate=True, no_store=True)
	def get(self, request, id):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')

		group = UserGroup.objects.get(user = request.user).name
		first_commission = CommissionManagement.objects.all().first()
		if group == "Service Seeker":
				user = User.objects.get(pk=id)

				user1 = User.objects.get(pk=request.user.id)

				# Last Commission contract 7 DEC Zad
				try:
					contract_list_for_commission = Contract.objects.filter(seeker=user1, provider=user).order_by('-id')
					print(contract_list_for_commission.first().contract_commission)
					if contract_list_for_commission:
						last_commission = contract_list_for_commission.first().contract_commission
					else:
						last_commission = 0
				except Exception as e:
					last_commission = 0
				# last commission contract ends
				caretypes = User_CareType.objects.filter(user=user1)


				caretypes = User_CareType.objects.filter(user=user)

				duty_list = User_Skill.objects.filter(user=user)
				group = UserGroup.objects.get(user=request.user).name
				provider = User.objects.get(groups__name="Service Provider",pk=id, is_active=True, publish=True)
				notification = Notification.objects.filter(user=request.user, is_read=False)
				notification_count = notification.count()
				price = User_CareType.objects.filter(user=user)
				cares = CareType.objects.all()
				
				line1 = ''
				line2 = ''
				if request.user.street_name:
					line1 = str(request.user.street_name).split('&line2=')[0]
					line2 = str(request.user.street_name).split('&line2=')[-1]
				try:

					last_contract = Contract.objects.filter(seeker=request.user,caretype_id=1).order_by('-added')[0]
					
					# last_contract = Contract.objects.filter(seeker=request.user).order_by('-added')[0]

				except:
					last_contract = 0
				
				try:
					last_contract2 = Contract.objects.filter(seeker=request.user,caretype_id=2).order_by('-added')[0]
					
				except:
					last_contract2 = 0
				try:
					last_contract3 = Contract.objects.filter(seeker=request.user,caretype_id=3).order_by('-added')[0]
					
				except:
					last_contract3 =0

				mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
				mssg_count = mssg.count()
				return render(request, 'templates/provider/book_provider.html', {
																'id': id,
																 'group': group,
																 'user': request.user,
																 'duty_list': duty_list,
																 'provider': provider,
																 'caretypes': caretypes,
																 'notifications': notification,
																 'notification_count': notification_count,
																 'range' : range(15),
																 'price': price,
																 'price_len': len(price)-1,
																 'mssg': mssg,
																 'line1':line1,
																 'line2':line2,	
				 												 'mssg_count': mssg_count,
				 												 'last_contract': last_contract,
															     'last_commission': last_commission,
				 												 'last_contract2': last_contract2,
				 												 'last_contract3': last_contract3,
				 												 'cares':cares,


																 })
		else:
			messages.add_message(request, messages.SUCCESS, "For booking this contract.Please login with service seeker.")
			return HttpResponseRedirect('/')

	def post(self,request,id):
		import datetime
		time_dict = {'firsthalf0': '07:00 am to 07:15 am', 'secondhalf0': '07:15 am to 07:30 am','thirdhalf0': '07:30 am to 07:45am','fourthhalf0': '07:45 am to 08:00 am',
		 			'firsthalf1': '08:00 am to 08:15 am', 'secondhalf1': '08:15 am to 08:30 am', 'thirdhalf1': '08:30 am to 08:45 am', 'fourthhalf1': '08:45 am to 09:00 am',
		  			'firsthalf2': '09:00 am to 09:15 am', 'secondhalf2': '09:15 am to 09:30 am', 'thirdhalf2': '09:30 am to 09:45 am', 'fourthhalf2': '09:45 am to 10:00 am',
		  			'firsthalf3': '10:00 am to 10:15 am', 'secondhalf3': '10:15 am to 10:30 am', 'thirdhalf3': '10:30 am to 10:45 am', 'fourthhalf3': '10:45 am to 11:00 am',
		  			'firsthalf4': '11:00 am to 11:15 am', 'secondhalf4': '11:15 am to 11:30 am', 'thirdhalf4': '11:30 am to 11:45 am','fourthhalf4': '11:45 am to 12:00 pm',
		  			'firsthalf5': '12:00 pm to 12:15 pm', 'secondhalf5': '12:15 pm to 12:30 pm', 'thirdhalf5': '12:30 pm to 12:45 pm', 'fourthhalf5': '12:45 pm to 13:00 pm',
		  			'firsthalf6': '13:00 pm to 13:15 pm', 'secondhalf6': '13:15 pm to 13:30 pm', 'thirdhalf6': '13:30 pm to 13:45 pm', 'fourthhalf6': '13:45 pm to 14:00 pm', 
		  			'firsthalf7': '14:00 pm to 14:15 pm', 'secondhalf7': '14:15 pm to 14:30 pm', 'thirdhalf7': '14:30 pm to 14:45 pm', 'fourthhalf7': '14:45 pm to 15:00 pm',
		  			'firsthalf8': '15:00 pm to 15:15 pm', 'secondhalf8': '15:15 am to 15:30 pm', 'thirdhalf8': '15:30 am to 15:45 pm', 'fourthhalf8': '15:45 am to 16:00 pm',
		  			'firsthalf9': '16:00 pm to 16:15 pm', 'secondhalf9': '16:15 pm to 16:30 pm', 'thirdhalf9': '16:30 pm to 16:45 pm', 'fourthhalf9': '16:45 pm to 17:00 pm',
		  			'firsthalf10': '17:00 pm to 17:15 pm', 'secondhalf10': '17:15 pm to 17:30 pm', 'thirdhalf10': '17:30 pm to 17:45 pm', 'fourthhalf10': '17:45 pm to 18:00 pm',
		  			'firsthalf11': '18:00 pm to 18:15 pm', 'secondhalf11': '18:15 pm to 18:30 pm', 'thirdhalf11': '18:30 pm to 18:45 pm','fourthhalf11': '18:45 pm to 19:00 pm',
		  			'firsthalf12': '19:00 pm to 19:15 pm', 'secondhalf12': '19:15 pm to 19:30 pm', 'thirdhalf12': '19:30 pm to 19:45 pm', 'fourthhalf12': '19:45 pm to 20:00 pm',
		  			'firsthalf13': '20:00 pm to 20:15 pm', 'secondhalf13': '20:15 pm to 20:30 pm', 'thirdhalf13': '20:30 pm to 20:45 pm','fourthhalf13': '20:45 pm to 21:00 pm',
		  			'firsthalf14': '21:00 pm to 21:15 pm', 'secondhalf14': '21:15 pm to 21:30 pm','thirdhalf14': '21:30 pm to 21:45 pm','fourthhalf14': '21:45 pm to 22:00 pm', }
		service_type = "Fixed"
		start_date = "None"
		end_date = "None"
		try:
			date1 = request.POST['startdate']
			start_date = datetime.datetime.strptime(str(date1), "%d-%m-%Y").date()

			date2 = request.POST['enddate']
			end_date = datetime.datetime.strptime(str(date2), "%d-%m-%Y").date()
		except:
			ongoing = request.POST['ongoing']
			service_type = "Ongoing"
			date1 = request.POST['startdate']
			start_date = datetime.datetime.strptime(str(date1), "%d-%m-%Y").date()
				
		provider_obj = User.objects.get(pk=id)
		care = CareType.objects.get(name=str(request.POST['caretype']))

		try:
			price = Contract.objects.filter(seeker_id=request.user.id,caretype=care,status='Completed').order_by('-added')[0].price
			price = request.POST['price']
		except:
			price = request.POST['price']
			# price = User_CareType.objects.get(caretype=care, user=request.user.id).price
		if service_type == "Fixed":
			new_end_date = end_date+datetime.timedelta(days=1)
			duration =  str(new_end_date - start_date).split(',')[0].split(' ')[0]

			try:
				# For Edit Contract
				contract_id = request.POST['User_Contract_Id']
				contract = Contract.objects.get(pk=contract_id)
				calendar = CalendarEvent.objects.filter(contract_id=contract).delete()
				contract_calendar = ContractCalendar.objects.filter(contract_id=contract).delete()
				duties = ContractDuties.objects.filter(contract=contract).delete()
				contract.price=price 
				contract.start_date=start_date 
				contract.end_date=end_date
				contract.line1=request.POST['line1'] 
				contract.line2=request.POST['line2'] 
				contract.county=request.POST['county'] 
				contract.city=request.POST['city']
				contract.post_code=request.POST['post_code'] 
				contract.service_receiver_address=request.POST['address'] 
				contract.care_for=request.POST['care_for']
				contract.status='Pending'
				contract.duties=dict(request.POST)['duty'] 
				contract.provider=provider_obj
				contract.caretype= care
				contract.service_type= service_type
				contract.save()
			except:
				# For Create Contract
				contract = Contract(seeker=request.user, price=price, start_date=start_date, end_date=end_date, line1=request.POST['line1'], line2=request.POST['line2'], county=request.POST['county'], city=request.POST['city'], post_code=request.POST['post_code'], service_receiver_address=request.POST['address'], care_for=request.POST['care_for'], provider=provider_obj, duties=dict(request.POST)['duty'], caretype=care, service_type=service_type)
				# Set contract commission
				get_latest_contract = Contract.objects.filter(seeker = request.user)
				if get_latest_contract:
					latest = get_latest_contract.latest('id')
					if latest.contract_commission > 0:
						contract.contract_commission = latest.contract_commission
				contract.save()
				name = "C00"+str(contract.id)
				contract.name=name
				contract.save()

			if "other_info" in request.POST:
				contract.other_info = request.POST['other_info']
				contract.save()
			

			if "additional_info" in request.POST:
				contract.other_req = request.POST['additional_info']
				contract.save()
			
			if contract.care_for == "self":
				service_receiver_name = str(request.user.first_name)+' ' + str(request.user.last_name)
				contract.service_receiver_name = service_receiver_name
				contract.save()
			
			if contract.care_for == "someoneelse":
				service_receiver_name = request.POST['receiver_name']
				contract.service_receiver_name = service_receiver_name
				contract.relation = request.POST['relation']
				contract.save()	
			
			for i in dict(request.POST)['duty']:
				skill = Skill.objects.get(name=str(i))
				contract_duty = ContractDuties()
				contract_duty.contract = contract
				contract_duty.duty = skill
				contract_duty.save()
			
			if price == None:
				price = 0

			# Calendar generation for Hourly fixed for selected days
			if int(care.id) == 3 or int(care.id) == 2:
				contract.duration = int(duration)
				contract.total_cost = float(price)*contract.duration
				contract.save()
			
			continous = False
			from datetime import timedelta
			date = start_date
			
			# Calendar generation for Over Night care
			if int(care.id) == 2:
				try:
					# Calculate for extra hours
					start_time = time_dict[str(dict(request.POST)['Ongoing_calendar'][0])].split('to')[0]
					end_time = time_dict[str(dict(request.POST)['Ongoing_calendar'][-1])].split('to')[-1]
					extra_hours = str(start_time) + ' to '+ str(end_time)
	 				contract.extra_hours = 	extra_hours
	 				contract.save()

	 				starttime = '21:00'
					starttime = datetime.datetime.strptime(starttime, '%H:%M').time()
					
					if 'am' in end_time:
						endtime = end_time.split('am')[0]
					if 'pm' in end_time:
						endtime = end_time.split('pm')[0]
					endtime = endtime.strip()
					endtime = datetime.datetime.strptime(endtime, '%H:%M').time()
					
					event = str(care.name).title()+' '+ str(contract.name)
					for i in range(int(duration)):
						event_start = datetime.datetime.combine(start_date, starttime) 
						event_end = datetime.datetime.combine(start_date, endtime)
						if i==0:
							calendar = CalendarEvent(status="Addmore", event=event, service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract)
						else:
							calendar = CalendarEvent(status="Continue", event=event, service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract)
						calendar.save()
						start_date = start_date+timedelta(1)

					# Calculate cost for extra hours
					total_hours = 15*len(list(dict(request.POST)['Ongoing_calendar']))
											
					totalMinutes = total_hours*int(duration)
					minutesPerHour = 60
					totalHours = totalMinutes // minutesPerHour
					care_type = CareType.objects.get(name="Hourly")
					try:
						price = Contract.objects.filter(seeker_id=request.user.id,caretype=care_type,status='Completed').order_by('-added')[0].price
					except:
						price = User_CareType.objects.get(caretype=care_type, user=provider_obj).price
					contract_price = totalHours*float(price)
					remainingMinutes = totalMinutes % minutesPerHour
					if remainingMinutes>0:
						half_hour_price = float(price)/minutesPerHour
						half_hour_price = remainingMinutes*half_hour_price
					else:
						half_hour_price = 0
					contract_price = contract_price+half_hour_price
					contract.total_cost = contract.total_cost+contract_price
					contract.save()
				except:
					contract.extra_hours = 0
					contract.save()
					starttime = '21:00'
					starttime = datetime.datetime.strptime(starttime, '%H:%M').time()
					endtime = '07:00'
					endtime = datetime.datetime.strptime(endtime, '%H:%M').time()

					event = str(care.name).title()+' '+ str(contract.name)  
					for i in range(int(duration)):
						event_start = datetime.datetime.combine(start_date, starttime) 
						event_end = datetime.datetime.combine(start_date, endtime)
						
						calendar = CalendarEvent(status="Continue", event=event, service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract)
						calendar.save()
						start_date = start_date+timedelta(1) 

				contract_calendar = CalendarEvent.objects.filter(contract_id=contract)
				for calendar_seq in contract_calendar:
					contract_calendar = ContractCalendar(service_provider=provider_obj, event_start=calendar_seq.event_start, event_end=calendar_seq.event_end, contract_id=contract, status=calendar_seq.status, event=calendar_seq.event)
					contract_calendar.save()

			# Calendar generation for Live In fixed 
			if int(care.id) == 3:
				starttime = '00:01'
				starttime = datetime.datetime.strptime(starttime, '%H:%M').time()
				endtime = '23:59'
				endtime = datetime.datetime.strptime(endtime, '%H:%M').time()

				event = str(care.name).title()+' '+ str(contract.name)  
				for i in range(int(duration)):
					event_start = datetime.datetime.combine(start_date, starttime) 
					event_end = datetime.datetime.combine(start_date, endtime)

					calendar = CalendarEvent(status="Generated", event=event, service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract)
					calendar.save()
					start_date = start_date+timedelta(1)

				contract_calendar = CalendarEvent.objects.filter(contract_id=contract)
				for calendar_seq in contract_calendar:
					contract_calendar = ContractCalendar(service_provider=provider_obj, event_start=calendar_seq.event_start, event_end=calendar_seq.event_end, contract_id=contract, status=calendar_seq.status, event=calendar_seq.event)
 					contract_calendar.save()

			# Calendar generation for Horly fixed 		
			if int(care.id) == 1:
				b = 0
				for k, v in dict(request.POST).items():
					if "Datewise" in str(k):
						b += 1
				datewise = []
				for k, v in dict(request.POST).items():
					if "Datewise" in str(k):
						datekey = k.split('Datewise')[1]
						datewise.append(int(datekey)) 

				datewise_len = max(datewise) + 1

				# Calculation for Hourly care
				if datewise_len>0:
# 				if b>0:
					total_hours = 0
					total_end_hours = 0
# 					for i in range(0, b):
# 						var = 'Datewise'+ str(i)
# 						if i == b-1:
# 							# Calculation for Continue for all
# 							last_day_hours = 30*len(list(dict(request.POST)[var]))
# 							last_date = "hourly_date"+str(i)
# 							last_booked_date = request.POST[last_date]
# 								
# 							last_date = datetime.datetime.strptime(str(last_booked_date), "%d-%m-%Y").date()
# 							new_end_date = end_date+datetime.timedelta(days=1)
# 							duration =  str(new_end_date - last_date).split(',')[0].split(' ')[0]
# 							
# 							total_end_hours += last_day_hours*int(duration)
# 							break
# 
# 						total_hours += 30*len(list(dict(request.POST)[var]))
					for i in range(0, datewise_len):
						var = 'Datewise'+ str(i)
						datewise_val = 0 if dict(request.POST).get(var)==None else len(list(dict(request.POST)[var])) 
  						if i == datewise_len-1:
  							last_day_hours = 15*datewise_val
  							last_date = "hourly_date"+str(i)
  							last_booked_date = request.POST[last_date]
  								
  							last_date = datetime.datetime.strptime(str(last_booked_date), "%d-%m-%Y").date()
  							new_end_date = end_date+datetime.timedelta(days=1)
  							duration =  str(new_end_date - last_date).split(',')[0].split(' ')[0]
  							
  							total_end_hours += last_day_hours*int(duration)
  							break
  						total_hours += 15*datewise_val

					totalMinutes = total_hours+total_end_hours
					minutesPerHour = 60
					totalHours = totalMinutes // minutesPerHour
					contract_price = totalHours*float(price)
					remainingMinutes = totalMinutes % minutesPerHour
					if remainingMinutes>0:
						half_hour_price = float(price)/minutesPerHour
						half_hour_price = remainingMinutes*half_hour_price
					else:
						half_hour_price = 0
					contract_price = contract_price+half_hour_price
					hour_duration = str(totalHours)+' '+'Hours'+', '+ str(remainingMinutes)+' '+'Minutes'
					contract.duration = hour_duration
					contract.total_cost = contract_price
 					contract.save()
					# Calendar generation for Hourly fixed for selected days
					event = str(care.name).title()+' '+ str(contract.name)
# 					for i in range(0, b):
					for i in range(0, datewise_len):
						var = 'Datewise'+ str(i)
						time = 30
						total_hours = 0
# 						if i == b-1:
						if i == datewise_len-1:
							continous = True
							
						if dict(request.POST).get(var)!=None:
							for item in dict(request.POST)[var]:
								start_time = time_dict[str(item)].split('to')[0]
								end_time = time_dict[str(item)].split('to')[-1]
	
								# timing = ContractTiming(contract=contract, date=date, start_time=start_time, end_time=end_time, hours=time, continous=continous)  
								# timing.save()
								
								if 'am' in start_time:
									s_time = start_time.split('am')[0]
								if 'pm' in start_time:
									s_time = start_time.split('pm')[0]
								s_time = s_time.strip()
								
								starttime = datetime.datetime.strptime(s_time, '%H:%M').time()
	
								if 'am' in end_time:
									e_time = end_time.split('am')[0]
								if 'pm' in end_time:
									e_time = end_time.split('pm')[0]
								e_time = e_time.strip()
								
								endtime = datetime.datetime.strptime(e_time, '%H:%M').time()
								
								event_start = datetime.datetime.combine(date, starttime) 
								event_end = datetime.datetime.combine(date, endtime)
	# 							if i == b-1:
								if i == datewise_len-1:
									calendar = CalendarEvent(event=event, service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract, status="Continue")
								else:
									calendar = CalendarEvent(event=event, service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract, status="Addmore")
								calendar.save()
								total_hours += 30 
						date = date+timedelta(1)
					
					# Calendar generation for Hourly fixed after Continue clicked
# 					continous_date = 'hourly_date'+str(b-1)
					continous_date = 'hourly_date'+str(datewise_len-1)
					continue_all =  request.POST[continous_date]

					continue_all1 = datetime.datetime.strptime(str(continue_all), "%d-%m-%Y").date()
					end_date = datetime.datetime.strptime(str(date2), "%d-%m-%Y").date()
					if str(continue_all1) != str(end_date):
# 						var = 'Datewise'+ str(b-1)
						var = 'Datewise'+ str(datewise_len-1)
						continue_date = datetime.datetime.strptime(str(continue_all), "%d-%m-%Y").date()
						new_calendar_date = continue_date+datetime.timedelta(days=1)
						duration =  str(end_date - continue_date).split(',')[0].split(' ')[0]

						generated_date = continue_date+datetime.timedelta(days=1)
						
						for i in range(0, int(duration)):
							for item in dict(request.POST)[var]:
								start_time = time_dict[str(item)].split('to')[0]
								end_time = time_dict[str(item)].split('to')[-1]
								if 'am' in start_time:
									s_time = start_time.split('am')[0]
								if 'pm' in start_time:
									s_time = start_time.split('pm')[0]
								s_time = s_time.strip()

								starttime = datetime.datetime.strptime(s_time, '%H:%M').time()

								if 'am' in end_time:
									e_time = end_time.split('am')[0]
								if 'pm' in end_time:
									e_time = end_time.split('pm')[0]
								e_time = e_time.strip()
								
								endtime = datetime.datetime.strptime(e_time, '%H:%M').time()
								
								event_start = datetime.datetime.combine(generated_date, starttime) 
								event_end = datetime.datetime.combine(generated_date, endtime)
								calendar = CalendarEvent(event=event, status='Generated' , service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract)
								calendar.save() 
							generated_date = generated_date+timedelta(1)

				contract_calendar = CalendarEvent.objects.filter(contract_id=contract)
				event_end = ''
				event_start = ''
				total_records = contract_calendar.count()
				count = 1
				for calendar_seq in contract_calendar:
					if not event_end and not event_start:
						event_start = calendar_seq.event_start
						event_end = calendar_seq.event_end
					elif event_end == calendar_seq.event_start:
						event_end = calendar_seq.event_end
						if count == total_records:
							contract_calendar = ContractCalendar(event=calendar_seq.event, service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract, status=calendar_seq.status)
							contract_calendar.save()	
					else:
						contract_calendar = ContractCalendar(event=calendar_seq.event, service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract, status=calendar_seq.status)
						contract_calendar.save()
						event_start = calendar_seq.event_start
						event_end = calendar_seq.event_end
					count = count+1
			else:
				pass

		if service_type == "Ongoing":
			from datetime import timedelta
			try:
				# For Edit Contract
				end_date = None
				contract_id = request.POST['User_Contract_Id']
				contract = Contract.objects.get(pk=contract_id)
				calendar = CalendarEvent.objects.filter(contract_id=contract).delete()
				duties = ContractDuties.objects.filter(contract=contract).delete()
				contract_calendar = ContractCalendar.objects.filter(contract_id=contract).delete()
				contract.price=price 
				contract.start_date=start_date
				contract.end_date=end_date 
				contract.line1=request.POST['line1'] 
				contract.line2=request.POST['line2'] 
				contract.county=request.POST['county'] 
				contract.city=request.POST['city']
				contract.post_code=request.POST['post_code'] 
				contract.service_receiver_address=request.POST['address'] 
				contract.care_for=request.POST['care_for']
				contract.status='Pending'
				contract.duties=dict(request.POST)['duty'] 
				contract.provider=provider_obj
				contract.caretype= care
				contract.service_type= service_type
				contract.save()
			except:
				# For Create Contract
				contract = Contract(seeker=request.user, price=price, start_date=start_date, line1=request.POST['line1'], line2=request.POST['line2'], county=request.POST['county'], city=request.POST['city'], post_code=request.POST['post_code'], service_receiver_address=request.POST['address'], care_for=request.POST['care_for'], status='Pending', provider=provider_obj, duties=dict(request.POST)['duty'], caretype=care, service_type=service_type)
				# contract.save()
				# name = "C00"+str(contract.id)
				# contract.name=name
				# contract.save()
				# Set Contract Commissions
				get_latest_contract = Contract.objects.filter(seeker = request.user)
				if get_latest_contract:
					latest = get_latest_contract.latest('id')
					if latest.contract_commission > 0:
						contract.contract_commission = latest.contract_commission
				contract.save()
				name = "C00"+str(contract.id)
				contract.name=name
				contract.save()
			
			if "other_info" in request.POST:
				contract.other_info = request.POST['other_info']
				contract.save()
			
			if "additional_info" in request.POST:
				contract.other_req = request.POST['additional_info']
				contract.save()

			if contract.care_for == "self":
				service_receiver_name = str(request.user.first_name)+' ' + str(request.user.last_name)
				contract.service_receiver_name = service_receiver_name
				contract.save()

			if contract.care_for == "someoneelse":
				service_receiver_name = request.POST['receiver_name']
				contract.service_receiver_name = service_receiver_name
				contract.relation = request.POST['relation']
				contract.save()	
			
			for i in dict(request.POST)['duty']:
				skill = Skill.objects.get(name=str(i))
				contract_duty = ContractDuties()
				contract_duty.contract = contract
				contract_duty.duty = skill
				contract_duty.save()

			if int(care.id) == 3 or int(care.id) == 2:
				contract.duration = "Ongoing"
				contract.total_cost = float(price)*7
				contract.save()

			# Calendar generation for live In
			if int(care.id) == 3:
				starttime = '00:01'
				starttime = datetime.datetime.strptime(starttime, '%H:%M').time()
				endtime = '23:59'
				endtime = datetime.datetime.strptime(endtime, '%H:%M').time()
  
				event = str(care.name).title()+' '+ str(contract.name)  
				for i in range(0,7):
					event_start = datetime.datetime.combine(start_date, starttime) 
					event_end = datetime.datetime.combine(start_date, endtime)

					calendar = CalendarEvent(status="Generated", event=event, service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract)
					calendar.save()
					start_date = start_date+timedelta(1)

				contract_calendar = CalendarEvent.objects.filter(contract_id=contract)
				for calendar_seq in contract_calendar:
					contract_calendar = ContractCalendar(service_provider=provider_obj, event_start=calendar_seq.event_start, event_end=calendar_seq.event_end, contract_id=contract, status=calendar_seq.status, event=calendar_seq.event)
					contract_calendar.save()

			# Calendar generation for Over Night
			if int(care.id) == 2:
				starttime = '21:00'
				starttime = datetime.datetime.strptime(starttime, '%H:%M').time()
				endtime = '07:00'
				endtime = datetime.datetime.strptime(endtime, '%H:%M').time()

				event = "Over Night "+ str(contract.name)  
				for i in range(0,7):
					event_start = datetime.datetime.combine(start_date, starttime) 
					event_end = datetime.datetime.combine(start_date, endtime)
					
					calendar = CalendarEvent(status="Generated", event=event, service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract)
					calendar.save()
					start_date = start_date+timedelta(1)

				contract_calendar = CalendarEvent.objects.filter(contract_id=contract)
				for calendar_seq in contract_calendar:
					contract_calendar = ContractCalendar(service_provider=provider_obj, event_start=calendar_seq.event_start, event_end=calendar_seq.event_end, contract_id=contract, status=calendar_seq.status, event=calendar_seq.event)
					contract_calendar.save()	

			if int(care.id) == 1:
				total_hours = 15*len(list(dict(request.POST)['Ongoing_calendar']))
											
				totalMinutes = total_hours
				minutesPerHour = 60
				totalHours = totalMinutes // minutesPerHour
				contract_price = totalHours*float(price)
				remainingMinutes = totalMinutes % minutesPerHour
				if remainingMinutes>0:
					half_hour_price = float(price)/minutesPerHour
					half_hour_price = remainingMinutes*half_hour_price
				else:
					half_hour_price = 0
				contract_price = contract_price+half_hour_price
				
				hour_duration = str(totalHours)+' '+'Hours'+', '+ str(remainingMinutes)+' '+'Minutes'
				
				contract.duration = hour_duration
				contract.total_cost = contract_price*7
				contract.save()

				# Calendar generation for Hourly
				event = str(care.name).title()+' '+ str(contract.name) 
				for i in range(0,7):
					for item in dict(request.POST)['Ongoing_calendar']:
						start_time = time_dict[str(item)].split('to')[0]
						end_time = time_dict[str(item)].split('to')[-1]
						if 'am' in start_time:
							s_time = start_time.split('am')[0]
						if 'pm' in start_time:
							s_time = start_time.split('pm')[0]
						s_time = s_time.strip()
							

						starttime = datetime.datetime.strptime(s_time, '%H:%M').time()

						if 'am' in end_time:
							e_time = end_time.split('am')[0]
						if 'pm' in end_time:
							e_time = end_time.split('pm')[0]
						e_time = e_time.strip()
						
						
						endtime = datetime.datetime.strptime(e_time, '%H:%M').time()
						
						event_start = datetime.datetime.combine(start_date, starttime) 
						event_end = datetime.datetime.combine(start_date, endtime)
						
						if i==0:
							calendar = CalendarEvent(event=event, status='Continue', service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract)
						else:
							calendar = CalendarEvent(event=event, status='Generated', service_provider=provider_obj, event_start=event_start, event_end=event_end, contract_id=contract)							
						calendar.save()
					start_date = start_date+timedelta(1)

				contract_calendar = CalendarEvent.objects.filter(contract_id=contract)
				event_end = ''
				event_start = ''
				total_records = contract_calendar.count()
				count = 1
				
				for calendar_seq in contract_calendar:
					if not event_end and not event_start:
						event_start = calendar_seq.event_start
						event_end = calendar_seq.event_end
					elif event_end == calendar_seq.event_start:
						event_end = calendar_seq.event_end
						if count == total_records:
							contract_calendar = ContractCalendar(service_provider=provider_obj, event=calendar_seq.event,  event_start=event_start, event_end=event_end, contract_id=contract, status=calendar_seq.status)
							contract_calendar.save()	
					else:
						contract_calendar = ContractCalendar(service_provider=provider_obj, event=calendar_seq.event, event_start=event_start, event_end=event_end, contract_id=contract, status=calendar_seq.status)
						contract_calendar.save()
						event_start = calendar_seq.event_start
						event_end = calendar_seq.event_end
					count = count+1
				else:
					pass
		try:
			request.POST['User_Contract_Id']

			notification = Notification(notification_type="contract", user=provider_obj)
			notification.content = "Your Contract " + str(contract.name) +" updated successfully."  
			notification.save()

			notification = Notification(notification_type="admincontract", user=provider_obj)
			notification.content = "Contract " + str(contract.name) +" updated successfully."
			notification.save()
			messages.add_message(request, messages.SUCCESS, "Your contract updated successfully.")
		except:
			subject = 'Carers Direct : New Booking'
			message_type = "New Contract"
			email = str(contract.provider.email)
			contract_name = contract.name
			push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)

			if request.is_secure():
				link='https://'+str(request.get_host())
			else:
				link='http://'+str(request.get_host())

			link = str(link)+"/dashboard/contracts/"

			if contract.seeker.telephone_number:
				telephone_number=contract.seeker.telephone_number
				number = telephone_number.replace(" ", "")
				seeker_message = "Your booking successfully done. Wait for carer response."
				send_notification(number, seeker_message)

			if contract.provider.telephone_number:
				telephone_number=contract.provider.telephone_number
				number = telephone_number.replace(" ", "")
				provider_message = "Dear "+str(contract.provider.first_name).title()+' '+str(contract.provider.last_name).title() +", a new contract "+ str(contract.name)+" has been created for you.\n Please refer to "+str(link)
				send_notification(number, provider_message)

			notification = Notification(notification_type="contract", user=provider_obj)
			notification.content = "A new contract " + str(contract.name) +" has been created for you.\n Please see in your booking list."  
			notification.save()

			notification = Notification(notification_type="admincontract", user=provider_obj)
			notification.content = "A new contract " + str(contract.name) +" has been created by "+ str(contract.seeker.first_name) + ' ' +str(contract.seeker.last_name) +" for " + str(contract.provider.first_name) +' '+str(contract.provider.last_name) +"."  
			notification.save()

			messages.add_message(request, messages.SUCCESS, "Thank you for completing your booking. Please wait to receive confirmation.")		

		url = "/dashboard/contracts/"
		return HttpResponseRedirect(url) 


class EditContractView(LoginRequiredMixin, View):
	@cache_control(no_cache=True, must_revalidate=True, no_store=True)
	def get(self, request, id):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')

		group = UserGroup.objects.get(user = request.user).name
		if group == "Service Seeker":
			contract = Contract.objects.get(pk=id)
			if contract.status == "Pending":
				user_id = contract.provider.id
				user = User.objects.get(pk=user_id)
				caretypes = User_CareType.objects.filter(user=user)
				duty_list = User_Skill.objects.filter(user=user)
				group = UserGroup.objects.get(user=request.user).name
				provider = User.objects.get(groups__name="Service Provider",pk=user_id, is_active=True, publish=True)
				notification = Notification.objects.filter(user=request.user, is_read=False)
				notification_count = notification.count()
				price = User_CareType.objects.filter(user=user)
				list1 = []
				duty = ContractDuties.objects.filter(contract=contract)
				extra_hours_list = []
				mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
				mssg_count = mssg.count()
				cares = CareType.objects.all()
				for i in duty:
					list1.append(str(i.duty.name))
				calendar = CalendarEvent.objects.filter(Q(status="Addmore")|Q(status="Continue"), contract_id=contract)
				
				query = """SELECT DISTINCT id, DATE( `carers_app_calendarevent`.`event_start` ) AS date
							FROM `carers_app_calendarevent`
							WHERE (`carers_app_calendarevent`.`status` = "Addmore" OR `carers_app_calendarevent`.`status` = "Continue") AND  `carers_app_calendarevent`.`contract_id_id` ='%s'""" %(str(id))
				count = CalendarEvent.objects.raw(query)
				
				list2 = []
				time_indexing = {
							'07:00:00':'firsthalf0','07:15:00':'secondhalf0','07:30:00':'thirdhalf0','07:45:00':'fourthhalf0',
							'08:00:00':'firsthalf1','08:15:00':'secondhalf1', '08:30:00':'thirdhalf1','08:45:00':'fourthhalf1',
							'09:00:00':'firsthalf2','09:15:00':'secondhalf2', '09:30:00':'thirdhalf2', '09:45:00':'fourthhalf2',
							'10:00:00':'firsthalf3','10:15:00':'secondhalf3', '10:30:00':'thirdhalf3', '10:45:00':'fourthhalf3', 
							'11:00:00':'firsthalf4', '11:15:00':'secondhalf4', '11:30:00':'thirdhalf4', '11:45:00':'fourthhalf4',
							'12:00:00':'firsthalf5','12:15:00':'secondhalf5', '12:30:00':'thirdhalf5',  '12:45:00':'fourthhalf5',
							'13:00:00':'firsthalf6', '13:15:00':'secondhalf6', '13:30:00':'thirdhalf6', '13:45:00':'fourthhalf6', 
							'14:00:00':'firsthalf7', '14:15:00':'secondhalf7', '14:30:00':'thirdhalf7', '14:45:00':'fourthhalf7',
							'15:00:00':'firsthalf8','15:15:00':'secondhalf8',  '15:30:00':'thirdhalf8', '15:45:00':'fourthhalf8', 
							'16:00:00':'firsthalf9','16:15:00':'secondhalf9',  '16:30:00':'thirdhalf9', '16:45:00':'fourthhalf9', 
							'17:00:00':'firsthalf10','17:15:00':'secondhalf10','17:30:00':'thirdhalf10','17:45:00':'fourthhalf10',
							'18:00:00':'firsthalf11','18:15:00':'secondhalf11','18:30:00':'thirdhalf11','18:45:00':'fourthhalf11', 
							'19:00:00':'firsthalf12','19:15:00':'secondhalf12', '19:30:00':'thirdhalf12','19:45:00':'fourthhalf12',
							'20:00:00':'firsthalf13','20:15:00':'secondhalf13', '20:30:00':'thirdhalf13','20:45:00':'fourthhalf13',
							'21:00:00':'firsthalf14','21:15:00':'secondhalf14','21:30:00':'thirdhalf14','21:45:00':'fourthhalf14' }

				date_dictonary = {}
				for i in count:
					date_value = i.event_start.strftime("%d-%m-%Y %H:%m:%s").split(" ")[0]
					if date_value in date_dictonary.keys():
						date_dictonary[date_value].append(str(time_indexing[i.event_start.strftime("%d-%m-%Y %H:%M:%S").split(" ")[1]]))
					else:
						date_dictonary[date_value] = []
						date_dictonary[date_value].append(str(time_indexing[i.event_start.strftime("%d-%m-%Y %H:%M:%S").split(" ")[1]]))

					list2.append(i.date)
				date_dictonary = json.dumps(date_dictonary)
				try:
					max_date = max(list2).day if len(list2) > 0 else 0
					min_date = min(list2).day if len(list2) > 0 else 0
					count_len = max(list2).day - min(list2).day 
				except:
					count_len = 0
				extra_time = {
				'07:00 am  to  07:15 am': ['firsthalf0'],
				'07:00 am  to  07:30 am': ['firsthalf0','secondhalf0'],
				'07:00 am  to  07:45am': ['firsthalf0','secondhalf0','thirdhalf0'],
				'07:00 am  to  08:00 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0'],
				'07:00 am  to  08:15 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1'],
				'07:00 am  to  08:30 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1'],
				'07:00 am  to  08:45 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1'],
				'07:00 am  to  09:00 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1'],
				'07:00 am  to  09:15 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2'],
				'07:00 am  to  09:30 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2'],
				'07:00 am  to  09:45 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2'],
				'07:00 am  to  10:00 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2'],
				'07:00 am  to  10:15 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3'],
				'07:00 am  to  10:30 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3'],
				'07:00 am  to  10:45 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3'],
				'07:00 am  to  11:00 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3','fourthhalf3'],
				'07:00 am  to  11:15 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3','fourthhalf3','firsthalf4'],
				'07:00 am  to  11:30 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3','fourthhalf3','firsthalf4','secondhalf4'],
				'07:00 am  to  11:45 am': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3','fourthhalf3','firsthalf4','secondhalf4','thirdhalf4'],
				'07:00 am  to  12:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3','fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4'],
				'07:00 am  to  12:15 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5'],
				'07:00 am  to  12:30 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5'],
				'07:00 am  to  12:45 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5'],
				'07:00 am  to  13:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5'],
				'07:00 am  to  13:15 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6'],
				'07:00 am  to  13:30 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6'],
				'07:00 am  to  13:45 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6'],
				'07:00 am  to  14:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6'],
				'07:00 am  to  14:15 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7'],
				'07:00 am  to  14:30 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7'],
				'07:00 am  to  14:45 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7'],
				'07:00 am  to  15:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7'],
				'07:00 am  to  15:15 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8'],
				'07:00 am  to  15:30 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8'],
				'07:00 am  to  15:45 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8'],
				'07:00 am  to  16:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8'],

				'07:00 am  to  16:15 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9'],
				'07:00 am  to  16:30 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9'],
				'07:00 am  to  16:45 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9'],
				'07:00 am  to  17:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9'],

				'07:00 am  to  17:15 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10'],
				'07:00 am  to  17:30 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10'],
				'07:00 am  to  17:45 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10'],
				'07:00 am  to  18:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10'],

				'07:00 am  to  18:15 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11'],
				'07:00 am  to  18:30 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11'],
				'07:00 am  to  18:45 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11'],
				'07:00 am  to  19:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11'],

				'07:00 am  to  19:15 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12'],
				'07:00 am  to  19:30 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12'],
				'07:00 am  to  19:45 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12','thirdhalf12'],
				'07:00 am  to  20:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12','thirdhalf12','fourthhalf12'],

				'07:00 am  to  20:15 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12','thirdhalf12','fourthhalf12','firsthalf13'],
				'07:00 am  to  20:30 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12','thirdhalf12','fourthhalf12','firsthalf13','secondhalf13'],
				'07:00 am  to  20:45 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12','thirdhalf12','fourthhalf12','firsthalf13','secondhalf13','thirdhalf13'],
				'07:00 am  to  21:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12','thirdhalf12','fourthhalf12','firsthalf13','secondhalf13','thirdhalf13','fourthhalf13'],

				'07:00 am  to  21:15 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12','thirdhalf12','fourthhalf12','firsthalf13','secondhalf13','thirdhalf13','fourthhalf13','firsthalf14'],
				'07:00 am  to  21:30 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12','thirdhalf12','fourthhalf12','firsthalf13','secondhalf13','thirdhalf13','fourthhalf13','firsthalf14','secondhalf14'],
				'07:00 am  to  21:45 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12','thirdhalf12','fourthhalf12','firsthalf13','secondhalf13','thirdhalf13','fourthhalf13','firsthalf14','secondhalf14','thirdhalf14'],
				'07:00 am  to  22:00 pm': ['firsthalf0','secondhalf0','thirdhalf0','fourthhalf0','firsthalf1','secondhalf1','thirdhalf1','fourthhalf1','firsthalf2','secondhalf2','thirdhalf2','fourthhalf2','firsthalf3','secondhalf3','thirdhalf3',
				'fourthhalf3','firsthalf4','secondhalf4','thirdhalf4','fourthhalf4','firsthalf5','secondhalf5','thirdhalf5','fourthhalf5','firsthalf6','secondhalf6','thirdhalf6','fourthhalf6','firsthalf7','secondhalf7','thirdhalf7','fourthhalf7','firsthalf8','secondhalf8','thirdhalf8','fourthhalf8','firsthalf9','secondhalf9','thirdhalf9','fourthhalf9','firsthalf10','secondhalf10','thirdhalf10','fourthhalf10','firsthalf11','secondhalf11','thirdhalf11','fourthhalf11','firsthalf12','secondhalf12','thirdhalf12','fourthhalf12','firsthalf13','secondhalf13','thirdhalf13','fourthhalf13','firsthalf14','secondhalf14','thirdhalf14','fourthhalf14'],

				}
			 	try:
			 		if int(contract.caretype.id) == 2 and int(contract.extra_hours) != 0:
			 			extra_hours_list = []
			 	except:
			 		if int(contract.caretype.id) == 2 and str(contract.extra_hours) != 0:
						extra_hours_list = json.dumps(extra_time[str(contract.extra_hours)])
				return render(request, 'templates/provider/edit_contract.html', {
																'id': id,
																 'group': group,
																 'user': request.user,
																 'duty_list': duty_list,
																 'provider': provider,
																 'caretypes': caretypes,
																 'notifications': notification,
																 'notification_count': notification_count,
																 'range' : range(15),
																 'price': price,
																 'price_len': len(price)-1,
																 'contract': contract,
																 'list1': list1,
																 'calendar': calendar,
# 																 'count': len(set(list2))-1,
																 'count': count_len,
																 'date_dictonary':mark_safe(date_dictonary),
																 'extra_hours_list': extra_hours_list,
																 'mssg': mssg,
				 												 'mssg_count': mssg_count,
				 												 'cares':cares,
																 })		
			else:
				messages.add_message(request, messages.SUCCESS, "You can not edit this contract because this contract already  " + str(contract.status).lower() + ' by service provider.')
				return HttpResponseRedirect('/dashboard/contracts/')

		else:
			messages.add_message(request, messages.SUCCESS, "For edit this contract, please login as service seeker.")
			return HttpResponseRedirect('/')


# changes by pavan for login required
class CompleteProfile(LoginRequiredMixin,View):
	login_url = '/login/?next=/dashboard/complete_profile/'

	def get(self,request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')

		list_user =[]
		user_care = []
		user_price = []
		user_qualifi = []
		user_interest = []

		group = UserGroup.objects.get(user = request.user).name
		if group != "Service Seeker" and request.user.profile_complete == 0:
			languages = Language.objects.filter(is_active=True)
			skills = Skill.objects.filter(is_active=True)
			household_skills = skills.filter(skill_type='House hold')
			special_skills = skills.filter(skill_type='Specialist Skill')
			duties = skills.filter(Q(skill_type='Duties')| Q(skill_type='House hold')| Q(skill_type='Personal Care'))
			personal_care_skills = ConditionExpertise.objects.filter(is_active =True)
			caretype = CareType.objects.filter(is_active=True)
			user_detail = User.objects.get(email=request.user)
			use_language = User_Language.objects.filter(user_id = request.user)
			qualifications = qualification.objects.filter(is_active=True)
			interest = Interest.objects.filter(is_active=True)
			if use_language:
				for i in use_language:
					list_user.append(str(i.language.name))
			user_exp = UserExperience.objects.filter(user_id = request.user)
			user_caretype = User_CareType.objects.filter(user_id = request.user)
			user_qualification = userqualification.objects.filter(user_id = request.user)
			if user_qualification:
				for i in user_qualification:
					user_qualifi.append(str(i.qualification.name))
			if user_caretype:
				for i in user_caretype:
					user_care.append(str(i.caretype.name))
			user_exp_value = request.user.experience
			year = ""
			month =""
			if user_exp_value:
				split_value = user_exp_value.split(" ")
				year = split_value[0]
				month = split_value[2]
			user_skill = User_Skill.objects.filter(	user_id = request.user)
			User_ConditionExpert = User_ConditionExpertise.objects.filter(user_id = request.user)
			user_document = UserDocument.objects.filter(user_id = request.user)
			user_interest_value = User_interest.objects.filter(user_id = request.user)
			if user_interest_value:
				for i in user_interest_value:
					user_interest.append(str(i.interest.name))
			return render(request, 'templates/provider/complete_profile.html', {'group': group,
																				'user': request.user,
																				'languages': languages,
																				'household_skills': household_skills,
																				'special_skills': special_skills,
																				'personal_care_skills':  personal_care_skills,
																				'duties': duties,
																				'caretype': caretype,
																				'user_detail':user_detail,
																				'user_language':list_user,
																				'user_exp':user_exp,
																				'user_care1':user_caretype,
																				'user_care':user_care,
																				'year':year,
																				'month':month,
																				'qualifications':qualifications,
																				'user_qualification':user_qualifi,
																				'user_skill': user_skill,
																				'User_ConditionExpertise':User_ConditionExpert,
																				'user_document':user_document,
																				'interest':interest,
																				'user_interest':user_interest
																		})
		else:
			return HttpResponseRedirect('/')

	def post(self, request):
		complete = ""
		user = User.objects.get(username=request.user)
		if 'fst1' in request.POST:
			complete = "1"
			experience = 0
			gender = request.POST['gender']
			try:
				image = request.FILES['profilepic']
			except:
				image = request.POST['hiddenimg']
				
			b  =  request.POST['dob']
			if len(b)>0:
				dob = datetime.datetime.strptime(str(request.POST['dob']), "%d-%m-%Y").date()
			
			address = request.POST['address']
			country = request.POST['country']
			city = request.POST['city']
			town = request.POST['town']
			postcode = request.POST['post_code']
			# Interest = request.POST['interest']
			employee1_name = request.POST['employee1_name']
			employee2_name = request.POST['employee2_name']
			employee3_name = request.POST['employee3_name']

			employee1_phone = request.POST['employee1_phone']
			employee2_phone = request.POST['employee2_phone']
			employee3_phone = request.POST['employee3_phone']

			# changes by pavan sharma
			exp1_start = request.POST['exp1_start']
			exp2_start = request.POST['exp2_start']
			exp3_start = request.POST['exp3_start']
			exp1_end = request.POST["exp1_end"]
			exp2_end = request.POST["exp2_end"]
			exp3_end = request.POST["exp3_end"]

			years_experience = request.POST['years_experience']
			months_experience = request.POST['months_experience']
			
			location = city.title()+'-'+postcode
			url = 'https://maps.googleapis.com/maps/api/geocode/json?address='+str(location)+'&key=AIzaSyDdJSTee3k9yMmw5gtZnQp0D-v082HNqos'
			r = requests.post(url=url, verify=False)
			if r.status_code == 200:
				import json, pprint
				data = json.loads(r.text)
				if str(data['status']) == "ZERO_RESULTS":
					pass
				else: 
					b = pprint.PrettyPrinter(indent=2)
					lat_long = data['results'][0]['geometry']['location']
					data = json.dumps(lat_long)
					lat = lat_long['lat']
					lng = lat_long['lng']
					user.lat = lat
					user.lng = lng
					user.save()
			else:
				messages.add_message(request, messages.INFO, "Some Error occured. Please fill in again")
				return HttpResponseRedirect('/dashboard')
			
			User_Language.objects.filter(user_id=request.user).delete()
			userqualification.objects.filter(user_id=request.user).delete()
			User_interest.objects.filter(user_id=request.user).delete()

			for language in dict(request.POST)['language_list']:
				language = Language.objects.get(pk=int(language))
				user_language = User_Language(user=user, language=language)
				user_language.save()

			for quali in dict(request.POST)['qualifications']:
				qualification_id = qualification.objects.get(pk=int(quali))
				user_skill = userqualification(user=user, qualification=qualification_id)
				user_skill.save()
	
			for interestid in dict(request.POST)['interest']:
				interest_id = Interest.objects.get(pk=int(interestid))
				user_interest = User_interest(user=user, interest= interest_id)
				user_interest.save()

			if years_experience != "" and months_experience != "":
				experience = str(years_experience) +' Year '+str(months_experience)+' months'
			
			user.image = image
			user.dob = dob
			user.gender = gender
			user.street_name = address
			user.city = city
			user.house_no = town
			user.country = country
			user.post_code = postcode
			user.experience = experience
			user.save()
			
			User_CareType.objects.filter(user_id=request.user).delete()
			for care in dict(request.POST)['caretype']:
				care_id = CareType.objects.get(pk=int(care))
				get_id = str(care_id.id)
				get_price_id = request.POST['price'+str(get_id)]
				user_care_obj = User_CareType(user=user, caretype= care_id, price = get_price_id )
				user_care_obj.save()
			UserExperience.objects.filter(user_id=request.user).delete()


			if  exp1_start != "":
				exp1_start = datetime.datetime.strptime(str(request.POST['exp1_start']), "%d-%m-%Y").date()
			else:
				exp1_start = None

			if  exp1_end != "":
				exp1_end = datetime.datetime.strptime(str(request.POST['exp1_end']), "%d-%m-%Y").date()
			else:
				exp1_end = None

			user_experience = UserExperience(user=user, employer_name=employee1_name, employer_phone= employee1_phone, start_date=exp1_start, end_date=exp1_end)
			user_experience.save()

			if  exp2_start != "":
				exp2_start = datetime.datetime.strptime(str(request.POST['exp2_start']), "%d-%m-%Y").date()
			else:
				exp2_start = None

			if  exp2_end != "":
				exp2_end = datetime.datetime.strptime(str(request.POST['exp2_end']), "%d-%m-%Y").date()
			else:
				exp2_end = None

			user_experience = UserExperience(user= user, employer_name=employee2_name, employer_phone= employee2_phone, start_date=exp2_start, end_date=exp2_end)
			user_experience.save()
			
			if  exp3_start != "":
				exp3_start = datetime.datetime.strptime(str(request.POST['exp3_start']), "%d-%m-%Y").date()
			else:
				exp3_start = None	

			if  exp3_end != "":
				exp3_end = datetime.datetime.strptime(str(request.POST['exp3_end']), "%d-%m-%Y").date()
			else:
				exp3_end = None

			user_experience = UserExperience(user=user, employer_name=employee3_name, employer_phone= employee3_phone, start_date=exp3_start, end_date=exp3_end)
			user_experience.save()
				
			if request.POST['fst1'] == "NEXT":
				if user.form_completed > 1 and user.form_completed != "":
					pass
				else:
					user.form_completed = complete
					user.save()


		if 'fst2' in request.POST:
			short_desc = request.POST['short_desc']
			complete = "2"
			User_Skill.objects.filter(user_id=request.user).delete()
			User_ConditionExpertise.objects.filter(user_id=request.user).delete()
			# for skill in dict(request.POST)['houseskill']:
			# 	skill = Skill.objects.get(pk=int(skill))
			# 	user_skill = User_Skill(user=user, skill=skill)
			# 	user_skill.save()
			for skill in dict(request.POST)['personalskill']:
				skill = ConditionExpertise.objects.get(pk=int(skill))
				user_skill = User_ConditionExpertise(user=user, expertise=skill, is_active=True)
				user_skill.save()
			for skill in dict(request.POST)['dutyskill']:
				skill = Skill.objects.get(pk=int(skill))
				user_skill = User_Skill(user=user, skill=skill)
				user_skill.save()
			for skill in dict(request.POST)['specialskill']:
				skill = Skill.objects.get(pk=int(skill))
				user_skill = User_Skill(user=user, skill=skill)
				user_skill.save()
			user1 = User.objects.get(username=request.user)
			user1.brief_description = short_desc
			user1.save()
			if request.POST['fst2'] == "NEXT":
				if user.form_completed > 1 and user.form_completed != "1":
					pass
				else:
					user1.form_completed = complete
					user1.save()

		if 'fst3' in request.POST:
			complete = "3"
			UserDocument.objects.filter(user_id=request.user).delete()
			user2 = User.objects.get(username=request.user)
			if 'pis_file' in request.FILES:
				pis_file = request.FILES['pis_file']
			else:
				pis_file = request.POST['pis_file1']
			if 'dbs_file' in request.FILES:
				dbs = request.FILES['dbs_file']
			else:
				dbs = request.POST['dbs_file1']

			if 'bank_file' in request.FILES:
				bank_file = request.FILES['bank_file']
			else:
				bank_file = request.POST['bank_file1']
			
			if 'dl_file' in request.FILES:
				dl_file = request.FILES['dl_file']
			else:
				dl_file = request.POST['dl_file1']
			if 'ubill_file' in request.FILES:	
				ubill_file = request.FILES['ubill_file']
			else:
				ubill_file = request.POST['ubill_file1']
			if 'pp' in request.FILES:
				pp = request.FILES['pp']
			else:
				pp = request.POST['pp1']
			if 'ref1' in request.FILES:
				ref1 = request.FILES['ref1']
			else:
				ref1 = request.POST['ref11']
			if 'ref2' in request.FILES:
				ref2 = request.FILES['ref2']
			else:
				ref2 = request.POST['ref22']
				# str(datetime.date.today())
			if ref1 != "" and ref2 == "":
				user_documents = UserDocument(user=user, dbs=dbs, insurance=pis_file,
					driving_license=dl_file, passport_photo= pp,
					bank_society_statement=bank_file, utility=ubill_file, reference1=ref1)
				user_documents.save()

			elif ref2 != "" and ref1 == "":
				user_documents = UserDocument(user=user, dbs=dbs, insurance=pis_file,
					driving_license=dl_file, passport_photo=pp,
					bank_society_statement=bank_file, utility=ubill_file, reference2=ref2)
				user_documents.save()

			elif ref1 != "" and ref2 != "":
				user_documents = UserDocument(user=user, dbs=dbs, insurance=pis_file,
					driving_license=dl_file, passport_photo=pp,
					bank_society_statement=bank_file, utility=ubill_file,
					reference2=ref2, reference1=ref1)
				user_documents.save()
			if request.POST['fst3'] == "NEXT":
				if user.form_completed > 3 and user.form_completed != "2":
					pass
				else:
					user2.form_completed = complete
					user2.save()

		if 'fst4' in request.POST:
			user3 = User.objects.get(username=request.user)
			user3.profile_complete = True
			user3.save()
		user4 = User.objects.get(username=request.user)	
		if user4.profile_complete == 1:
			messages.add_message(request, messages.SUCCESS, "Thanks for providing this information. We are processing your application which will be going live shortly.")
			return HttpResponseRedirect('/dashboard/contracts/')
		else:
			return HttpResponseRedirect('/provider/complete_profile')


class BillingInformation(LoginRequiredMixin, View):
	login_url = '/login/?next=/dashboard/billing_information/'

	def get(self,request):
		group = UserGroup.objects.get(user = request.user).name
		return render(request, 'templates/provider/billing_information.html', {'group': group,
																			'user': request.user,
																			})

	def post(self,request):
		return HttpResponseRedirect('/provider/complete_profile/')


class GenerateInvoice(LoginRequiredMixin, View):
	login_url = '/login/?next=/dashboard/invoice/'

	@cache_control(no_cache=True, must_revalidate=True, no_store=True)
	def get(self,request, id):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')

		contract = Contract.objects.filter(service_type="Ongoing")
		if request.is_secure():
			url='https://'+str(request.get_host())+str(request.path)
		else:
			url='http://'+str(request.get_host())+str(request.path)
		today = datetime.date.today()
		group = UserGroup.objects.get(user = request.user).name
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.count()
		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		if group == "Service Provider":
			try:
# 				contract = Contract.objects.get(id=int(id))
				billing = Invoice.objects.get(id=id)
				contract = Contract.objects.get(name=billing.contract)
				user = User.objects.get(username=request.user)
# 				payments = Payment.objects.filter(user=user,invoice=id).order_by('-added')
				payments = Payment.objects.filter(invoice=id,contract=billing.contract)
				refunded_amount = 0.00
	  			paid_amount = 0.00
	  			commission_amount = 0.00
	  			total_amount = 0.00
				ask_release_note = ''
	  			commission_obj = ContractCommission.objects.filter(contract=payments[0].contract)
				commission_amount = 0.00
				if commission_obj:
					commission_amount = commission_obj[0].commission_get
				for payment in payments:
					if payment.request_state == 'Ask For Refund' or payment.mssg == 'Amount Refunded':
	 					refunded_amount = payment.actual_refund if payment.payment_state=='Paid' else 0.00
					elif payment.request_state == 'Ask For Release' or payment.request_state == 'Service Received' or payment.mssg == 'Care Complete':
	 					paid_amount = payment.actual_refund if payment.payment_state=='Paid' else 0.00
						# ask_release_note = payment.ask_release_note
				total_amount = paid_amount
# 				if contract.provider == request.user and (contract.status == "confirmed" or contract.status =="Confirmed" or contract.status =="accepted" or contract.status =="Accepted" or contract.status =="Completed"): 
				try:
					invoice = Invoices.objects.get(contract=contract)
				except:
					due_date = today+datetime.timedelta(days=7)
					contract_price = int(contract.total_cost)
					half_hour_price = 0
					if contract.service_type == "Fixed" and contract.caretype.name == "Hourly":
						hours = contract.duration.split(',')[0].split(' ')[0]
						contract_price = int(hours)*int(contract.price)
						if contract.duration.split(',')[-1].split(' ')[0] > 0:
							half_hour_price = int(contract.sprice)/2
						else:
							half_hour_price = 0

					if contract.service_type == "Ongoing" and (contract.caretype.name == "Live In" or contract.caretype.name == "Over Night"):
						contract_price = int(contract.total_cost)
						half_hour_price = 0

					subtotal = contract_price+half_hour_price
					invoice = Invoices(description=contract.duties, contract=contract, send_date=today, due_date=due_date, subtotal=subtotal, total=subtotal)
					invoice.save()
				return render(request, 'templates/provider/invoice.html', {'contract': contract,
																			'group': group,
																			'user': request.user,
																			'show': True,
																			'today': today,
																			'notifications': notification,
																			'notification_count': notification_count,
																			'mssg': mssg,
							 												'mssg_count': mssg_count,
							 												'url': url,
							 												'payments':payments[0],
							 												'commission_amount':commission_amount,
							 												'refunded_amount':refunded_amount,
																	 		'paid_amount':paid_amount,
							 												'total_amount':total_amount,
																	 		})
# 				else:
# 					messages.add_message(request, messages.INFO, 'You are not authorised to generate invoice for this contract.')
# 					return render(request, 'templates/provider/invoice.html', {	'group': group,
# 																				'user': request.user,
# 																				'show': False,
# 																				'today': 'dummy',
# 																				'notifications': notification,
# 														 						'notification_count': notification_count,
# 														 						'mssg': mssg,
# 								 												'mssg_count': mssg_count,})
			except:
				messages.add_message(request, messages.INFO, 'Such contract  is never created')
				return render(request, 'templates/provider/invoice.html', {'group': group,
																			'show': False, 
																			'user': request.user,
																			'today': 'dummy',
																			'notifications': notification,
														 					'notification_count': notification_count,
														 					'mssg': mssg,
								 											'mssg_count': mssg_count,})		
		
		if group == "Service Seeker":
 			billing = Invoice.objects.get(id=id)
 			total = int(billing.total)*100
 			user = User.objects.get(username=request.user)
 			contract_obj = Contract.objects.get(name = billing.contract)
#    			payments = Payment.objects.filter(user=user,invoice=id).order_by('-added')
			payments = Payment.objects.filter(invoice=id,contract=billing.contract)
   			refunded_amount = 0.00
  			paid_amount = 0.00
  			commission_amount = 0.00
  			total_amount = 0.00
			ask_refund_note = ''
  			commission_obj = ContractCommission.objects.filter(contract=payments[0].contract)
			commission_amount = 0.00
			if commission_obj:
				commission_amount = commission_obj[0].commission_get
# 			if payments[0].request_state == 'Deposit' or payments[0].mssg == 'Deposit for contract':
# 				paid_amount = 0.00
# 			elif payments[0].request_state == 'Ask For Refund' or payments[0].mssg == 'Amount Refunded':
# 				refunded_amount = payments[0].actual_refund
# 				paid_amount = payments[0].contract.total_cost - refunded_amount
# 			elif payments[0].request_state == 'Ask For Release' or payments[0].mssg == 'Care Complete':
# 				refunded_amount = float(payments[0].contract.total_cost) - (float(payments[0].actual_refund) + float(commission_amount))
# 				paid_amount = payments[0].actual_refund
# 			else:
# 				paid_amount = float(payments[0].contract.total_cost) - float(commission_amount)
			for payment in payments:
				if payment.request_state == 'Ask For Refund' or payment.mssg == 'Amount Refunded':
 					refunded_amount = payment.actual_refund if payment.payment_state=='Paid' else 0.00
					# ask_refund_note = payment.ask_refund_note
				elif payment.request_state == 'Ask For Release' or payment.request_state == 'Service Received' or payment.mssg == 'Care Complete':
					paid_amount = float(payment.contract.total_cost) - float(refunded_amount)
			total_amount = paid_amount
			return render(request, 'templates/seeker/invoice.html', {'group': group,
																			'total': total,
																			'show': False, 
															 				'user': request.user,
																			'today': 'dummy',
																			'billing': billing,
																			'notifications': notification,
														 					'notification_count': notification_count,
														 					'mssg': mssg,
		 																	'mssg_count': mssg_count,
		 																	'url': url,
																	 		'payments':payments[0],
																	 		'refunded_amount':refunded_amount,
																	 		'paid_amount':paid_amount,
																	 		'total_amount':total_amount,
																	 		})


	def post(self,request, id):
		b = download_invoice_pdf(request, id)
		host = request.get_host()	
		contract = Contract.objects.get(pk=id)
		#link='http: //'+str(host)+"/invoice_pdf/"+str(id)+ '/'
		subject = "Booking Invoice"
		# message = "Dear " + str(contract.seeker.first_name) + ' ' +str(contract.seeker.last_name) + ','+ '\n' +"Your invoice for the "+ 'Service Title '+ "has been created. Please click "+link+" to download."+'\n' +"Thanks"+'\n' +"Direct Carers Team"
		message = "Dear " + str(contract.seeker.first_name).title() + ' ' +str(contract.seeker.last_name).title() + ','+ '\n' +" Your invoice for the services provided by "+str(contract.provider.first_name).title() + ' ' +str(contract.provider.last_name).title() +" has been created."
		email = contract.seeker.email
		try:
			destination = "/home/ubuntu/Project/Carers_Website/"
			mail = EmailMessage(subject, message, settings.EMAIL_HOST_USER, [email])
			mail.attach_file(destination+'Invoice.pdf')
			mail.send()
			messages.add_message(request, messages.SUCCESS, 'Successfully sent invoice to client')
		except:
			messages.add_message(request, messages.INFO,"Something went wrong.Please try again letter.")
		return HttpResponseRedirect("/dashboard/contracts/")

# @login_required
def download_invoice_pdf(request, id):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	try:
		joinduites = ''
		contract_detail = Contract.objects.get(pk=id)
		if contract_detail.duties:
			if ',' in contract_detail.duties:
				splitduties = eval(contract_detail.duties)
				for d in splitduties:
					joinduites += str(d)+ ','
			else:
				joinduites = contract_detail.duties
		else:
			joinduites = ''

		if request.is_secure():
			image_url='https://'+str(request.get_host())
		else:
			image_url='http://'+str(request.get_host())

		data = {
			'contract':contract_detail,
			'joinduites' :joinduites.rstrip(','),
			'url':image_url
		}
		# Create a Django response object, and specify content_type as pdf
		response = HttpResponse(content_type='application/pdf')
		response['Content-Disposition'] = 'attachment; filename="Invoice.pdf"'

		html = get_template('templates/email_templates/provderpdf.html').render(data)
		
		destination = "/home/ubuntu/Project/Carers_Website/"
		filename = "Invoice.pdf"
		file = open(destination + filename, "w+b")

		pisaStatus = pisa.CreatePDF(
		html.encode('utf-8'), dest=file, encoding='utf-8')
		# if error then show some funy view
		if pisaStatus.err:
			return HttpResponse('We had some errors <pre>' + html + '</pre>')
		return response	
	except:
		messages.add_message(request, messages.SUCCESS,"Something went wrong.Please try again letter.")
		return HttpResponseRedirect('/dashboard/billing/')


def save_invoice_pdf(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	
	try:
		joinduites = ''
		contract_id = request.POST['contract_id']
		refunded_amount = request.POST['refunded_amount']
		paid_amount = request.POST['paid_amount']
		commission_amount = request.POST['commission_amount']
		total_amount = request.POST['total_amt']
		release_reason = request.POST['release_reason']
		contract_detail = Contract.objects.get(pk=int(contract_id))
		if contract_detail.duties:
			splitduties = eval(contract_detail.duties)
			for d in splitduties:
				joinduites += str(d)+ ','
		else:
			joinduites = ''

		if request.is_secure():
			image_url='https://'+str(request.get_host())
		else:
			image_url='http://'+str(request.get_host())
		
		data = {
			'contract':contract_detail,
			'refunded_amount':refunded_amount,
			'release_reason':release_reason,
			'paid_amount':paid_amount,
			'commission_amount':commission_amount,
			'total_amount':total_amount,
			'joinduites' :joinduites.rstrip(','),
			'url':image_url
		}
		# Create a Django response object, and specify content_type as pdf
		response = HttpResponse(content_type='application/pdf')
		response['Content-Disposition'] = 'attachment; filename="Invoice.pdf"'

		html = get_template('templates/email_templates/provderpdf.html').render(data)
		
		pisaStatus = pisa.CreatePDF(
		html, dest=response, )
		# if error then show some funy view
		if pisaStatus.err:
			return HttpResponse('We had some errors <pre>' + html + '</pre>')
		return response
	except:
		messages.add_message(request, messages.SUCCESS, 'Something went wrong. Please try again letter.')
		return HttpResponseRedirect('/dashboard/contracts/')


def download_seeker_invoice_pdf(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')
	try:
		joinduites = ''
		contract_id = request.POST['contract_id']
		refunded_amount = request.POST['refunded_amount']
		paid_amount = request.POST['paid_amount']
		total_amount = request.POST['total_amt']
		refund_reason = request.POST['refund_reason']
		invoice_detail = Invoice.objects.get(pk= int(contract_id))
		if invoice_detail.contract.duties:
			splitduties = eval(invoice_detail.contract.duties)
			for d in splitduties:
				joinduites += str(d)+ ','
		else:
			joinduites = ''

		if request.is_secure():
			image_url='https://'+str(request.get_host())
		else:
			image_url='http://'+str(request.get_host())
		user = User.objects.get(username=request.user)
		payments = Payment.objects.filter(user=user, invoice=int(contract_id)).order_by('-added')
		data = {
			'billing':invoice_detail,
			'joinduites' :joinduites.rstrip(','),
			'url':image_url,
			'payments':payments[0],
			'refunded_amount':refunded_amount,
			'refund_reason':refund_reason,
			'paid_amount':paid_amount,
			'total_amount':total_amount
		}
		
		# Create a Django response object, and specify content_type as pdf
		response = HttpResponse(content_type='application/pdf')
		response['Content-Disposition'] = 'attachment; filename="Invoice.pdf"'

		html = get_template('templates/email_templates/seekerinvoice.html').render(data)
		
		pisaStatus = pisa.CreatePDF(
		html, dest=response, )
		# if error then show some funy view
		if pisaStatus.err:
			return HttpResponse('We had some errors <pre>' + html + '</pre>')
		return response
	except:
		messages.add_message(request, messages.SUCCESS, 'Something went wrong. Please try again')
		return HttpResponseRedirect('/dashboard/contracts/')


class Blogs(View):

	def get(self,request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		
		group = ''
		now = datetime.datetime.now()
		months_choices = []
		for i in range(1,13):
			months_choices.append(str(datetime.date(2008, i, 1).strftime('%B')) +' '+ str(now.year))
		try:
			group = UserGroup.objects.get(user = request.user.id).name
		except:
			pass
		blog_category = Blog_Category.objects.filter(is_active=True)
		try:
			get_search = request.GET['search']
		except:
			 get_search = None
		try:
			month = request.GET['month']
		except:
			 month = None

		if get_search != None:
			blogs = Blog.objects.filter(is_active=True,title__istartswith=str(get_search))
		elif month != None:
			blogs = Blog.objects.filter(is_active=True, added__date__month=str(month))
		else:
			blogs = Blog.objects.filter(is_active=True)

		paginator = Paginator(blogs, 10) # Show 25 contacts per page

		page = request.GET.get('page')
		try:
			blogs = paginator.page(page)
		except PageNotAnInteger:
			# If page is not an integer, deliver first page.
			blogs = paginator.page(1)
		except EmptyPage:
			# If page is out of range (e.g. 9999), deliver last page of results.
			blogs= paginator.page(paginator.num_pages)
		return render(request, 'templates/blog.html',{'blogs': blogs,
													'blog_category': blog_category,'group':group,'months_choices':months_choices})


class Blog_Detail(View):

	def get(self,request, id):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		group = ''
		try:
			group = UserGroup.objects.get(user = request.user.id).name
		except:
			pass

		try:
			blog = Blog.objects.get(pk= id, is_active=True)
			related_post = Blog.objects.filter(~Q(pk=id), category = blog.category, is_active=True)
			return render(request, 'templates/blog_detail.html',{'blog': blog,'group':group,'related_post':related_post})
		except:
			messages.add_message(request, messages.SUCCESS, 'No such blog found')
			return HttpResponseRedirect('/blog/')



class Blog_Filter(View):

	def get(self,request, id):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		
		now = datetime.datetime.now()
		months_choices = []
		for i in range(1,13):
			months_choices.append(str(datetime.date(2008, i, 1).strftime('%B')) +' '+ str(now.year))
		blog_category = Blog_Category.objects.filter(is_active=True)
		category = Blog_Category.objects.filter(is_active=True, pk=id)
		blogs = Blog.objects.filter(category=category, is_active=True)

		paginator = Paginator(blogs, 10) # Show 25 contacts per page
		page = request.GET.get('page')
		try:
			blogs = paginator.page(page)
		except PageNotAnInteger:
			# If page is not an integer, deliver first page.
			blogs = paginator.page(1)
		except EmptyPage:
			# If page is out of range (e.g. 9999), deliver last page of results.
			blogs= paginator.page(paginator.num_pages)
		return render(request, 'templates/blog_filter.html',{'blogs': blogs,
													'blog_category': blog_category,'months_choices':months_choices})


class Contact_Us(View):

	def get(self,request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		
		form = ContactForm()
		return render(request, 'templates/contact_us.html',{'form': form})

	def post(self,request):
		if "Searchcarer" in request.POST:
			url = request.POST['url']
			name = request.POST['name']
			email = request.POST['email']
			contact_number = request.POST['contact_number'].replace(" ","")
			post_code = request.POST['postcode']
			message = "No provider found for postcode = "+str(post_code)
			admin_message = Admin_Message(name=str(name), email=str(email), contact_number=int(contact_number), message=message)
			admin_message.save()
			messages.add_message(request, messages.SUCCESS, 'Thanks for your support. We will revert you soon.')
			return HttpResponseRedirect(str(url))
		else:
			form = ContactForm(request.POST or None)
			if form.is_valid: 
				form.save()
			else:
				messages.add_message(request, messages.SUCCESS, 'Something gone wrong. Please fill again')
				return HttpResponseRedirect('/contact_us')
			messages.add_message(request, messages.SUCCESS, 'Thanks for connecting to us. We will revert you soon.')
			return HttpResponseRedirect('/contact_us')


@method_decorator(login_required, name='dispatch')
class Messaging(View):

	def dispatch(self, *args, **kwargs):
		return super(Messaging, self).dispatch(*args, **kwargs)

	def get(self, request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		from datetime import datetime
		group = UserGroup.objects.get(user = request.user).name
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.count()
		today = datetime.today().date()	
		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		count = 0
		name = str(request.user.first_name).title() +' '+ str(request.user.last_name).title()
		
		if "AllChat" in request.GET:
			import json
			list1 = []
			user = User.objects.get(username=request.GET['receiver'])
			data = UserChat.objects.filter(Q(sender = request.user)|Q(sender= user), Q(receiver = request.user)|Q(receiver= user)).order_by('-added')[::-1]
			unread = UserChat.objects.filter(Q(sender = request.user)|Q(sender= user), Q(receiver = request.user)|Q(receiver= user), is_read=False)
			unread.update(is_read=True)

			for data_itm in data:
				dict1 = {}
				dict1['sender'] = str(data_itm.sender.first_name).title() +' '+str(data_itm.sender.last_name).title()
				dict1['mssg'] = data_itm.mssg
				dict1['receiver'] = str(data_itm.receiver.first_name).title() +' '+str(data_itm.receiver.last_name).title()
				# dict1['time'] = str(data_itm.added.date().strftime('%d-%m-%Y'))
				dict1['time'] = str(data_itm.added)[:16]
				if request.user.id == data_itm.sender.id:
					dict1['is_login'] = True
				else:
					dict1['is_login'] = False

				list1.append(dict1)
			
			data1 = json.dumps(list1)			
			return HttpResponse(data1)
			
		if group == "Service Seeker":
			b = User.objects.get(username=request.user)
			a = UserChat.objects.filter(Q(sender = request.user)|Q(sender= b), Q(receiver = request.user)|Q(receiver= b)).order_by('added')
			# senders = User.objects.filter(groups__name="Service Provider", is_active=True)
			rooms = Room.objects.filter(user1=request.user)
			try:
				request.GET['user_id']
				return render(request, 'templates/message.html',{'group': group,
																'user_id': request.GET['user_id'],
																'rooms':  rooms,
																'notifications': notification,
																'notification_count': notification_count,
																'today': today,
																'mssg': mssg,
																'count': count,
																'name':name, 
		 														'mssg_count': mssg_count,
																})
			except:
				return render(request, 'templates/message.html',{'group': group,
																'name':name,
																'rooms':  rooms,
																'notifications': notification,
																'notification_count': notification_count,
																'today': today,
																'mssg': mssg,
																'count': count,
		 														'mssg_count': mssg_count,
																})
		elif group == "Service Provider":
			rooms = Room.objects.filter(user2=request.user)
			return render(request, 'templates/message.html',{'group': group,
															'user': request.user,
															'name':name,
															'rooms':  rooms,
															'notifications': notification,
															'notification_count': notification_count,
															'today': today,
															'mssg': mssg,
		 													'mssg_count': mssg_count,
															})

	def post(self, request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		from datetime import datetime
		group = UserGroup.objects.get(user = request.user).name
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.count()
		today = datetime.today().date()
		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		full_name = str(request.user.first_name).title() +' '+ str(request.user.last_name).title()
		if "SearchChat" in request.POST:
			group = UserGroup.objects.get(user = request.user).name
			name = request.POST['username']
			room = []
			try:
				if group == "Service Seeker":
					room_obj = Room.objects.filter(Q(user2__first_name__istartswith=name)|Q(user2__last_name__istartswith=name), user1=request.user)

				if group == "Service Provider":
					room_obj = Room.objects.filter(Q(user1__first_name__istartswith=name)|Q(user1__last_name__istartswith=name), user2=request.user)					
				
				for rooms in room_obj:
					room.append(rooms)
			except:
				room_obj = Room.objects.filter(Q(user2=request.user)|Q(user1=request.user))
				for chat_room in room_obj:
					room.append(chat_room)

			if len(room)<1:
				room = 0
			return render(request, 'templates/single_user_message.html', {'group': group,
															'user': request.user,
															'rooms':  room,
															'notifications': notification,
															'notification_count': notification_count,
															'today': today,
															'mssg': mssg,
		 													'mssg_count': mssg_count,
		 													'name': full_name
															})


		if "SendMessage" in request.POST:
			group = UserGroup.objects.get(user = request.user).name
			user_id = request.POST['username']
			
			if group == "Service Seeker":
				user2 = User.objects.get(pk=user_id)
				try:
					Room.objects.get(user1=request.user, user2=user2)
				except ObjectDoesNotExist:
					Room.objects.create(title='Chatroom', user1=request.user, user2=user2)
			
			if group == "Service Provider":
				user1 = User.objects.get(pk=user_id)
				try:
					Room.objects.get(user1=user1, user2=request.user)
				except ObjectDoesNotExist:
					Room.objects.create(title='Chatroom', user2=request.user, user1=user1)
			rooms = 0
			
			if group == "Service Seeker":
				rooms = Room.objects.filter(user2=user2, user1=request.user)

			if group == "Service Provider":
				rooms = Room.objects.filter(user1=user1, user2=request.user)

			return render(request, 'templates/single_user_message.html', {'group': group,
															'user': request.user,
															'notifications': notification,
															'notification_count': notification_count,
															'today': today,
															'rooms': rooms,
															'mssg': mssg,
		 													'mssg_count': mssg_count,
		 													'name': full_name
															})


@method_decorator(login_required, name='dispatch')			
class Calendar(View):
	@cache_control(no_cache=True, must_revalidate=True, no_store=True)
	def get(self, request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		
		group = UserGroup.objects.get(user = request.user).name
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.count()

		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		
		if request.is_secure():
			seeker_link='https://'+str(request.get_host())+"/dashboard/contracts/"
		else:
			seeker_link='http://'+str(request.get_host())+"/dashboard/contracts/"

		if request.is_secure():
			provider_link='https://'+str(request.get_host())+"/dashboard/contract_detail/"
		else:
			provider_link='http://'+str(request.get_host())+"/dashboard/contract_detail/"

		import json
		import datetime
		data = []
		calendar_data = []
		try:
			user = User.objects.get(username = request.user)
			if group == "Service Seeker":
				contracts = Contract.objects.filter(seeker=user)
				for item in contracts:
					calendar = ContractCalendar.objects.filter(contract_id=item.id, is_active=True)	
					for item in calendar:
						event = str(item.event).split(' ')[0]+' '+ "'"+str(item.event).split(' ')[-1]+"'"
						calendar_dict = {}
						calendar_dict['start'] = item.event_start
						calendar_dict['end'] = item.event_end
						calendar_dict['id'] = item.id
						calendar_dict['title'] = event
						calendar_dict['contract'] = item.contract_id.id
						data.append(calendar_dict)
						
					def myconverter(o):
					    if isinstance(o, datetime.date): 
					        return o.__str__()

					calendar_data = json.dumps(data, default = myconverter)
					
			else:
				try:
					contracts = Contract.objects.filter(provider=user)
					for item in contracts:
						calendar = ContractCalendar.objects.filter(contract_id=item.id, is_active=True)	
						for item in calendar:
							event = str(item.event).split(' ')[0]+' '+ "'"+str(item.event).split(' ')[-1]+"'"
							calendar_dict = {}
							calendar_dict['start'] = item.event_start
							calendar_dict['end'] = item.event_end
							calendar_dict['id'] = item.id
							calendar_dict['title'] = event
							calendar_dict['contract'] = item.contract_id.id
							data.append(calendar_dict)
							
						
						def myconverter(o):
						    if isinstance(o, datetime.date): 
						        return o.__str__()

						calendar_data = json.dumps(data, default = myconverter)
					
				except:
					pass
		except:
			pass	
		
		return render(request, 'templates/calendar.html', {'group': group,
		 'user': request.user, 'data': calendar_data,
		 'notifications': notification,
		 'notification_count': notification_count, 'mssg': mssg, 'mssg_count': mssg_count,
		 'seeker_url': seeker_link, 'provider_url': provider_link,})

	def post(self, request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		group = UserGroup.objects.get(user = request.user).name
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.count()

		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		
		if request.is_secure():
			seeker_link='https://'+str(request.get_host())+"/dashboard/contracts/"
		else:
			seeker_link='http://'+str(request.get_host())+"/dashboard/contracts/"

		if request.is_secure():
			provider_link='https://'+str(request.get_host())+"/dashboard/contract_detail/"
		else:
			provider_link='http://'+str(request.get_host())+"/dashboard/contract_detail/"

		import json
		import datetime
		data = []
		calendar_data = []
		contract = request.POST['contract_name']
		user = User.objects.get(username=request.user)
		try:
			if group == "Service Provider":
				contract = Contract.objects.get(name=str(contract),provider = request.user)
			else:
				contract = Contract.objects.get(name=str(contract),seeker = request.user)
			name = contract.name
			calendar = ContractCalendar.objects.filter(contract_id=contract)
			for item in calendar:
				calendar_dict = {}
				calendar_dict['title'] = item.event
				calendar_dict['start'] = item.event_start
				calendar_dict['end'] = item.event_end
				calendar_dict['id'] = item.id
				calendar_dict['contract'] = item.contract_id.id
				data.append(calendar_dict)
		except:
			messages.add_message(request, messages.INFO, "Invalid contract reference")
			

			name = ''
		def myconverter(o):
		    if isinstance(o, datetime.datetime):
		        return o.__str__()

		calendar_data = json.dumps(data, default = myconverter)

		return render(request, 'templates/calendar.html', {'group': group,
		 'user': request.user, 'data': calendar_data,
		 'notifications': notification,
		 'notification_count': notification_count, 'mssg': mssg, 'mssg_count': mssg_count,
		 'seeker_url': seeker_link, 'provider_url': provider_link,'name':name})


@login_required
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def contract_detail(request, id):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')

	user = User.objects.get(username = request.user)
	group = UserGroup.objects.get(user = request.user).name
	if group != "Service Seeker":
		try:
			contract = Contract.objects.get(pk = id)
		except:
			return HttpResponseRedirect('/')
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.count()
		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		return render(request, 'templates/provider/contract_detail.html',{'group': group,
			 'user': request.user, 'contract': contract, 'notifications': notification,
			 'notification_count': notification_count, 'mssg': mssg, 'mssg_count': mssg_count,})
	else:
		return HttpResponseRedirect('/')

def contract_values(request):
	if request.method == "POST":
		response = HttpResponse(content_type='text/csv')
		filename = "commission.csv"
		response['Content-Disposition'] = u'attachment; filename="{0}"'.format(filename)
		ilewriter = csv.writer(response)
		ilewriter.writerow(["Date", "Provider Name", "Seeker Name", "Contract Name",
							"Total Cost", "Release Amount", "Admin Commission", "Commission %"])

		month = str(request.POST['Month'])
		from_date = str(request.POST['FromDate'])
		to_date = str(request.POST['ToDate'])
		if month:
			month_split = month.split("-")
			year = int(str(month_split[0]))
			mnth = int(str(month_split[1]))
			num_days = calendar.monthrange(year, mnth)[1]
			days = [day for day in range(1, num_days + 1)]

			from_date = month + '-' + str(days[0])
			to_date = month + '-' + str(days[-1] )
			
		for reg in Payment.objects.filter(added__date__gte = from_date, added__date__lte = to_date,  request_state='Deposit', payment_state= 'Paid').order_by('-added'):
			csv_list = []
			date_commission = reg.added.strftime('%Y-%m-%d %H:%M:%S')
			try:
				csv_list = [date_commission]
				csv_list.extend([str(reg.contract.provider.first_name) + ' ' + str(reg.contract.provider.last_name),
					 str(reg.contract.seeker.first_name) + ' ' + str(reg.contract.seeker.last_name),
					 reg.contract, float(reg.contract.total_cost)])
				commision_object =ContractCommission.objects.filter(contract_id=reg.contract.id)
				if commision_object:
					for commission_value in commision_object:
						csv_list.extend([commission_value.released_amount, round(float(commission_value.commission_get),2),
						 round((commission_value.commission_get * 100) / commission_value.released_amount)])
						break
				else:
					csv_list.extend([0.0, 0.0, 0.0])
		
			except ContractCommission.DoesNotExist:
				pass

			ilewriter.writerow(csv_list)

			
		return response

class Reports(View):

	def get(self, request):
		available_apps = [{
		'app_url': u'/admin/auth/', 
		'models': [{
				'perms': {u'add': True, u'change': True, u'delete': True},
				'admin_url': u'/admin/auth/group/', 
				'object_name': 'Group', 'name': u'Groups', 
				'add_url': u'/admin/auth/group/add/'}], 
		'has_module_perms': True, 
		'name': u'Authentication and Authorization', 'app_label': 'auth'}, 
		{'app_url': u'/admin/carers_app/', 
		'models': [{'perms': {u'add': False, u'change': True, u'delete': True}, 
		'admin_url': u'/admin/carers_app/admin_message/', 
		'object_name': 'Admin_Message', 'name': u'Admin_ messages'}, 
		{'perms': {u'add': True, u'change': True, u'delete': True}, 
		'admin_url': u'/admin/carers_app/banner/', 
		'object_name': 'Banner', 'name': u'Banners', 'add_url': u'/admin/carers_app/banner/add/'}, 
		{'perms': {u'add': True, u'change': True, u'delete': True}, 
		'admin_url': u'/admin/carers_app/blog_category/', 
		'object_name': 'Blog_Category', 
		'name': u'Blog_ categorys', 'add_url': u'/admin/carers_app/blog_category/add/'}, 
		{'perms': {u'add': True, u'change': True, u'delete': True}, 
		'admin_url': u'/admin/carers_app/blog/', 
		'object_name': 'Blog', 'name': u'Blogs', 'add_url': u'/admin/carers_app/blog/add/'}, 
		{'perms': {u'add': True, u'change': True, u'delete': True}, 
		'admin_url': u'/admin/carers_app/calendarevent/', 
		'object_name': 'CalendarEvent', 'name': u'Calendar events', 
		'add_url': u'/admin/carers_app/calendarevent/add/'}, 
		{'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/cardtype/', 'object_name': 'CardType', 'name': u'Card types', 'add_url': u'/admin/carers_app/cardtype/add/'}, {'perms': {u'add': False, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/caretype/', 'object_name': 'CareType', 'name': u'Care types'}, {'perms': {u'add': True, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/cmspages/', 'object_name': 'CMSPages', 'name': u'Cms pagess', 'add_url': u'/admin/carers_app/cmspages/add/'}, {'perms': {u'add': False, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/commissionmanagement/', 'object_name': 'CommissionManagement', 'name': u'Commission managements'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/conditionexpertise/', 'object_name': 'ConditionExpertise', 'name': u'Condition expertises', 'add_url': u'/admin/carers_app/conditionexpertise/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/contractcalendar/', 'object_name': 'ContractCalendar', 'name': u'Contract calendars'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/contractcommission/', 'object_name': 'ContractCommission', 'name': u'Contract commissions'}, {'perms': {u'add': False, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/contract/', 'object_name': 'Contract', 'name': u'Contracts'}, {'perms': {u'add': True, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/emailtemplate/', 'object_name': 'EmailTemplate', 'name': u'Email templates', 'add_url': u'/admin/carers_app/emailtemplate/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/helpmessage/', 'object_name': 'HelpMessage', 'name': u'Help messages'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/interest/', 'object_name': 'Interest', 'name': u'Interests', 'add_url': u'/admin/carers_app/interest/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/invoice/', 'object_name': 'Invoice', 'name': u'Invoices'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/language/', 'object_name': 'Language', 'name': u'Languages', 'add_url': u'/admin/carers_app/language/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/notification/', 'object_name': 'Notification', 'name': u'Notifications'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/payment/', 'object_name': 'Payment', 'name': u'Payments'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/providerpaymentdetails/', 'object_name': 'ProviderPaymentDetails', 'name': u'Provider payment detailss', 'add_url': u'/admin/carers_app/providerpaymentdetails/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/skill/', 'object_name': 'Skill', 'name': u'Skills', 'add_url': u'/admin/carers_app/skill/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/useralert/', 'object_name': 'UserAlert', 'name': u'User alerts', 'add_url': u'/admin/carers_app/useralert/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/usercard/', 'object_name': 'UserCard', 'name': u'User cards', 'add_url': u'/admin/carers_app/usercard/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/userdocument/', 'object_name': 'UserDocument', 'name': u'User documents'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/user_caretype/', 'object_name': 'User_CareType', 'name': u'User_ care types', 'add_url': u'/admin/carers_app/user_caretype/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/user_skill/', 'object_name': 'User_Skill', 'name': u'User_ skills'}, {'perms': {u'add': False, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/user/', 'object_name': 'User', 'name': u'Users'}], 'has_module_perms': True, 'name': 'Carers_App', 'app_label': 'carers_app'}]
		# all_sites = WeakSet()
		# print all_sites

		# from django.contrib.admin.sites import AdminSite
		# b = AdminSite(object)

		# available_apps = b.get_app_list(request)
		# print available_apps
		return render(request, 'templates/admin/reports.html', {'available_apps': available_apps})


def users_data(request):
	if request.method=="GET":
		import json
		data = {}
		date = request.GET['date']

		month = request.GET['month']
		if len(month)>0:
			date = month.split('-')
			try:
				user = User.objects.filter(date_joined__date__month=str(date[1]), date_joined__date__year=str(date[0]))	
				data['total_count'] = user.count()
				data['seeker'] = user.filter(Q(groups__name="SS")|Q(groups__name="Service Seeker")).count()
				data['provider'] = user.filter(Q(groups__name="SP")|Q(groups__name="Service Provider")).count()
				data['active_users'] = user.filter(is_active=True).count()
				data['inactive_users'] = user.filter(is_active=False).count()
				data = json.dumps(data)
				return HttpResponse(data)
			except:
				pass
		if len(date)>0:
			try:
				user = User.objects.filter(date_joined__date=date)
				data['total_count'] = user.count()
				data['seeker'] = user.filter(Q(groups__name="SS")|Q(groups__name="Service Seeker")).count()
				data['provider'] = user.filter(Q(groups__name="SP")|Q(groups__name="Service Provider")).count()
				data['active_users'] = user.filter(is_active=True).count()
				data['inactive_users'] = user.filter(is_active=False).count()
				data = json.dumps(data)
				return HttpResponse(data)
			except:
				pass


def contracts_data(request):
	if request.method=="GET":
		import json
		data = {}
		date = request.GET['date']
		month = request.GET['month']
		if len(month)>0:
			date = month.split('-')
			try:
				contracts = Contract.objects.filter(added__date__year=str(date[0]), added__date__month=str(date[1]))	
				data['total_count'] = contracts.count()
				contracts = Contract.objects.filter(updated__date__year=date[0], updated__date__month=date[1])
				data['accepted'] = contracts.filter(status__iexact="accepted").count()
				data['rejected'] = contracts.filter(status__iexact="rejected").count()
				data['completed'] = contracts.filter(status__iexact="completed").count()
				data['cancelled'] = contracts.filter(Q(status__iexact="cancelled")|Q(status__iexact="terminated")).count()
				data = json.dumps(data)
				return HttpResponse(data)
			except:
				pass
		if len(date)>0:
			try:
				contracts = Contract.objects.filter(added__date=date)
				data['total_count'] = contracts.count()
				contracts = Contract.objects.filter(updated__date=date)
				data['accepted'] = contracts.filter(status__iexact="accepted").count()
				data['rejected'] = contracts.filter(status__iexact="rejected").count()
				data['completed'] = contracts.filter(status__iexact="completed").count()
				data['cancelled'] = contracts.filter(Q(status__iexact="cancelled")|Q(status__iexact="terminated")).count()
				data = json.dumps(data)
				return HttpResponse(data)
			except:
				pass


def payments_data(request):
	if request.method=="GET":
		import json
		data = {}
		date = request.GET['date']
		month = request.GET['month']
		if len(month)>0:
			date = month.split('-')
			try:
				amount = Invoice.objects.filter(due_date__date__year=date[0],due_date__date__month=date[1]).aggregate(Sum('subtotal'))
				if amount['subtotal__sum'] == None:
					data['total_amount'] = 0
				else:	
					data['total_amount'] = amount['subtotal__sum']

				amount_received = Invoice.objects.filter(payment_received_date__date__year=date[0],payment_received_date__date__month=date[1], paid=True).aggregate(Sum('subtotal'))
				if amount_received['subtotal__sum'] == None:
					data['amount_received'] = 0
				else:
					data['amount_received'] = amount_received['subtotal__sum']	
				
				data['amount_pending'] = data['total_amount'] - data['amount_received']
				data = json.dumps(data)
				return HttpResponse(data)
			except:
				pass
		if len(date)>0:
			try:
				amount = Invoice.objects.filter(due_date__date=date).aggregate(Sum('subtotal'))
				
				if amount['subtotal__sum'] == None:
					data['total_amount'] = 0
				else:	
					data['total_amount'] = amount['subtotal__sum']

				amount_received = Invoice.objects.filter(payment_received_date__date=date, paid=True).aggregate(Sum('subtotal'))

				if amount_received['subtotal__sum'] == None:
					data['amount_received'] = 0
				else:
					data['amount_received'] = amount_received['subtotal__sum']
				data['amount_pending'] = data['total_amount'] - data['amount_received']
				data = json.dumps(data)
				return HttpResponse(data)
			except:
				pass


@login_required
def manage_calendar(request):
	if request.is_secure():
		link='https://'+str(request.get_host())
	else:
		link='http://'+str(request.get_host())
	import json
	import datetime
	data = []
	date = datetime.datetime.now().date
	available_apps = [{'app_url': u'/admin/auth/', 'models': [{'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/auth/group/', 'object_name': 'Group', 'name': u'Groups', 'add_url': u'/admin/auth/group/add/'}], 'has_module_perms': True, 'name': u'Authentication and Authorization', 'app_label': 'auth'}, {'app_url': u'/admin/carers_app/', 'models': [{'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/banner/', 'object_name': 'Banner', 'name': u'Banners', 'add_url': u'/admin/carers_app/banner/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/blog/', 'object_name': 'Blog', 'name': u'Blogs', 'add_url': u'/admin/carers_app/blog/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/calendarevent/', 'object_name': 'CalendarEvent', 'name': u'Calendar events', 'add_url': u'/admin/carers_app/calendarevent/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/cmspages/', 'object_name': 'CMSPages', 'name': u'Cms pagess', 'add_url': u'/admin/carers_app/cmspages/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/contract/', 'object_name': 'Contract', 'name': u'Contracts', 'add_url': u'/admin/carers_app/contract/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/emailtemplate/', 'object_name': 'EmailTemplate', 'name': u'Email templates', 'add_url': u'/admin/carers_app/emailtemplate/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/helpmessage/', 'object_name': 'HelpMessage', 'name': u'Help messages', 'add_url': u'/admin/carers_app/helpmessage/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/invoice/', 'object_name': 'Invoice', 'name': u'Invoices', 'add_url': u'/admin/carers_app/invoice/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/user/', 'object_name': 'User', 'name': u'Users', 'add_url': u'/admin/carers_app/user/add/'}], 'has_module_perms': True, 'name': 'Carers_App', 'app_label': 'carers_app'}]
	if request.method == "POST":
		contract = request.POST['contract_name']
		# provider = request.POST['provider_name']
		providers = 0
		try:
			contract = Contract.objects.get(name=str(contract))
		except:
			return HttpResponseRedirect('/admin/carers_app/view_calendar/')
		url = link+"/admin/carers_app/contractcalendar/?event="+str(contract.caretype)+"+"+str(contract)
		calendar = ContractCalendar.objects.filter(contract_id=contract)	
		for item in calendar:
			calendar_dict = {}
			calendar_dict['start'] = item.event_start
			calendar_dict['end'] = item.event_end
			calendar_dict['id'] = item.id
			calendar_dict['title'] = item.event
			data.append(calendar_dict)
			
		def myconverter(o):
		    if isinstance(o, datetime.date): 
		        return o.__str__()

		# data = json.dumps(data, default = myconverter)
		data = json.dumps(data, default=myconverter)

		return render(request, 'templates/admin/calendar.html', {'providers':providers,
	 'date':date, 'available_apps': available_apps, 'data': data, 'verification':"True",
	 'contract':contract, "url": url})

	providers = User.objects.filter(Q(groups__name__iexact='SP')|Q(groups__name__iexact='Service Provider'))
	data = []
	calendar = ContractCalendar.objects.filter(is_active=True)	
	for item in calendar:
		calendar_dict = {}
		calendar_dict['start'] = item.event_start
		calendar_dict['end'] = item.event_end
		calendar_dict['id'] = item.id
		calendar_dict['title'] = item.event
		data.append(calendar_dict)
		
	def myconverter(o):
	    if isinstance(o, datetime.date): 
	        return o.__str__()

	data = json.dumps(data, default=myconverter)

	return render(request, 'templates/admin/calendar.html', {'providers':providers,
	 'date':date, 'available_apps': available_apps, 'data': data, 'verification':"False", 'contract_name': ''})


@login_required
def calendarview(request):
	if request.method=="GET":
		import json
		import datetime
		data = []
		
		contract = request.GET['contract']
		provider = request.GET['provider']
		
		try:
			contract = Contract.objects.get(name=str(contract))
			caretype = contract.caretype.name
			url = str(caretype)+'+'+str(contract.name)
			provider_name = str(contract.provider.first_name) +' '+str(contract.provider.last_name)
			
			if not str(provider) in provider_name:
				data = "This contract is not related to this provider"
				return JsonResponse(data,safe=False) 
			
			calendar = ContractCalendar.objects.filter(contract_id=contract)	
			
			for item in calendar:
				calendar_dict = {}
				calendar_dict['start'] = item.event_start
				calendar_dict['end'] = item.event_end
				calendar_dict['id'] = item.id
				calendar_dict['title'] = item.event
				data.append(calendar_dict)
				
			def myconverter(o):
			    if isinstance(o, datetime.date): 
			        return o.__str__()

			# data = json.dumps(data, default = myconverter)
			return JsonResponse(data, safe=False)
		except:
			data = "No such contract found"
			return JsonResponse(data,safe=False)			


def otp_generator(size=6, chars=string.digits):
	return ''.join(random.choice(chars) for _ in range(size))		


def encrypt_val(clear_text):
    enc_secret = AES.new(settings.ENCRYPT_KEY[:32])
    tag_string = (str(clear_text) +
                  (AES.block_size -
                   len(str(clear_text)) % AES.block_size) * "\0")
    cipher_text = base64.b64encode(enc_secret.encrypt(tag_string))
    return cipher_text


def decrypt_val(cipher_text):
    dec_secret = AES.new(settings.ENCRYPT_KEY[:32])
    raw_decrypted = dec_secret.decrypt(base64.b64decode(cipher_text))
    clear_val = raw_decrypted.decode().rstrip("\0")
    return clear_val


def send_otp(request):
	if request.method == "GET":
		contract_name = request.GET['contract']
		contract = Contract.objects.get(name=str(contract_name))
		seeker = contract.seeker.telephone_number
		provider = contract.provider.telephone_number
		
		seeker_otp = otp_generator()
		if seeker:
			number = seeker.replace(" ", "")
			message = "You requested for add extra hours or for timing change for contract "+ str(contract_name) +". Your verification code is "+str(seeker_otp)
			send_notification(number, message)

		subject = 'Carers Direct : Calendar Update'
		message_type = "Calendar Update"
		email = str(contract.seeker.email)
		contract_name = str(contract_name)
		otp = seeker_otp
		push_email = EmailMessageNotification(request, subject, message_type, email, contract_name, otp=seeker_otp)

		
		provider_otp = otp_generator()
		if provider:
			number = provider.replace(" ", "")
			message = "You requested for add extra hours or for timing change for contract "+ str(contract_name) +". Your verification code is "+str(provider_otp)
			send_notification(number, message)

		subject = 'Carers Direct : Calendar Update'
		message_type = "Calendar Update"
		email = str(contract.provider.email)
		contract_name = str(contract_name)
		otp = provider_otp
		push_email = EmailMessageNotification(request, subject, message_type, email, contract_name, otp=provider_otp)

		data = {}
		data['seeker_otp'] = str(seeker_otp)
		data['provider_otp'] = str(provider_otp)
		#data = json.dumps(data)
		return JsonResponse(data)


def update_event(request):
	if request.method == "POST":
		event_start = request.POST['event_start']
		event_end = request.POST['event_end']
		event_id = request.POST['event_id']

		if int(event_id) == 0:
			event_name = request.POST['event_name']
			contract_name = str(event_name).split(' ')[-1]
			contract = Contract.objects.get(name=str(contract_name))
			provider = contract.provider
			event = ContractCalendar()
			event_start = datetime.datetime.strptime(event_start[:-5], "%a %b %d %Y %H:%M:%S %Z")
			event_end = datetime.datetime.strptime(event_end[:-5], '%a %b %d %Y %H:%M:%S %Z')
			
			event.event_start = event_start
			event.event_end = event_end
			event.event = str(event_name)
			event.contract_id = contract
			event.service_provider = provider
			event.status = 'Generated'
			event.save()
		else:
			event = ContractCalendar.objects.get(id=int(event_id))
			event_start = datetime.datetime.strptime(event_start[:-5], "%a %b %d %Y %H:%M:%S %Z")
			event_end = datetime.datetime.strptime(event_end[:-5], '%a %b %d %Y %H:%M:%S %Z')
			event.event_start = event_start
			event.event_end = event_end
			event.save()
		data = 'Calendar Update Successfully.'
		return HttpResponse(data)


def testimonials(request):
	return render(request, 'templates/testimonials.html', {})


class AdvanceSearch(View):

	def get(self, request):
		if request.user.is_superuser or request.user.is_staff:
			return HttpResponseRedirect('/admin/')
		
		language = Language.objects.all()
		skill = Skill.objects.all()
		expertise = ConditionExpertise.objects.all()
		if request.user.is_anonymous:
			return render(request, "templates/advance_search.html", {'languages': language,
																'skills': skill,
																'range' : range(15),
																'expertise_list': expertise})
		else:
			try:
				group = UserGroup.objects.get(user=request.user).name
			except Exception as e:
				if request.user.is_superuser or request.user.is_staff:
					return HttpResponseRedirect('/admin/')
			notification = Notification.objects.filter(user=request.user, is_read=False)
			notification_count = notification.count()
			mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
			mssg_count = mssg.count()
			return render(request, "templates/seeker/advance_search.html", {'languages': language,
																'skills': skill,
																'range' : range(15),
																'expertise_list': expertise,
																'group': group,
																'notification': notification,
																'notification_count': notification_count,
																'mssg': mssg,
																'mssg_count': mssg_count,
																})


def AdvanceSearchResult(request):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')

	time_dict = {'firsthalf0': '07:00 am to 07:30 am', 'secondhalf0': '07:30 am to 08:00 am',
					'firsthalf1': '08:00 am to 08:30 am', 'secondhalf1': '08:30 am to 09:00 am',
					'firsthalf2': '09:00 am to 09:30 am', 'secondhalf2': '09:30 am to 10:00 am',
					'firsthalf3': '10:00 am to 10:30 am', 'secondhalf3': '10:30 am to 11:00 am', 
					'firsthalf4': '11:00 am to 11:30 am', 'secondhalf4': '11:30 am to 12:00 pm', 
					'firsthalf5': '12:00 pm to 12:30 pm', 'secondhalf5': '12:30 pm to 13:00 pm', 
					'firsthalf6': '13:00 pm to 13:30 pm', 'secondhalf6': '13:30 pm to 14:00 pm', 
					'firsthalf7': '14:00 pm to 14:30 pm', 'secondhalf7': '14:30 pm to 15:00 pm',
					'firsthalf8': '15:00 pm to 15:30 pm', 'secondhalf8': '15:30 am to 16:00 pm',
					'firsthalf9': '16:00 pm to 16:30 pm', 'secondhalf9': '16:30 pm to 17:00 pm',
					'firsthalf10': '17:00 pm to 17:30 pm', 'secondhalf10': '17:30 pm to 18:00 pm',
					'firsthalf11': '18:00 pm to 18:30 pm', 'secondhalf11': '18:30 pm to 19:00 pm',
					'firsthalf12': '19:00 pm to 19:30 pm', 'secondhalf12': '19:30 pm to 20:00 pm',
					'firsthalf13': '20:00 pm to 20:30 pm', 'secondhalf13': '20:30 pm to 21:00 pm',
					'firsthalf14': '21:00 pm to 21:30 pm', 'secondhalf14': '21:30 pm to 22:00 pm'}

	skill = []
	language = []
	expertise = []
	start_date = "None"
	end_date = "None"
	gender = "None"
	caretype = "None"
	check_skill = []
	check_expertise = []
	check_language = []

	query = """SELECT distinct auth_user.id, auth_user.username FROM auth_user inner join auth_user_groups on auth_user.id = auth_user_groups.user_id inner JOIN carers_app_user_skill ON auth_user.id = carers_app_user_skill.user_id inner JOIN carers_app_user_language ON auth_user.id=carers_app_user_language.user_id inner JOIN carers_app_user_conditionexpertise ON auth_user.id=carers_app_user_conditionexpertise.user_id inner JOIN carers_app_user_caretype ON auth_user.id=carers_app_user_caretype.user_id inner join carers_app_language on carers_app_language.id = carers_app_user_language.language_id inner join carers_app_conditionexpertise on carers_app_conditionexpertise.id = carers_app_user_conditionexpertise.expertise_id inner join carers_app_skill on carers_app_skill.id = carers_app_user_skill.skill_id inner join carers_app_caretype on carers_app_caretype.id =carers_app_user_caretype.caretype_id where auth_user.is_active=1 and auth_user.publish=1"""
	if 'gender' in request.GET:
		if request.GET['gender']:
			if request.GET['gender'] == 'Male':
				gender = "Male"
				query = query + " and (auth_user.gender = 'Male')"
			elif request.GET['gender'] == 'Female':
				gender = "Female"
				query = query + " and (auth_user.gender = 'Female')"

	if 'caretype' in request.GET:
		if request.GET['caretype']:
			if request.GET['caretype'] == 'Hourly':
				caretype = "Hourly"
				care_name = CareType.objects.get(id=1).name
			elif request.GET['caretype'] == 'Over Night':
				caretype = "Over Night"
				care_name = CareType.objects.get(id=2).name
			elif request.GET['caretype'] == 'Live In':
				caretype = "Live In"
				care_name = CareType.objects.get(id=3).name
			query = query + " and (carers_app_caretype.name = "+"'"+str(care_name)+"'"+")"

	for k,vals in request.GET.lists():
		if k == "skill":
			for v in vals:
				if v:
					skill.append(v)
		elif k == "language":
			for v in vals:
				if v:
					language.append(v)
		elif k == "expertise":
			for v in vals:
				if v:
					expertise.append(v)

	if len(skill)>0:
		query = query+ " and ("
		for data in skill:
			check_skill.append(data)
			if str(data) == str(skill[-1]):
				query = query+" carers_app_skill.name='%s'"%(str(data))
			else:
				query = query+" carers_app_skill.name='%s' or "%(str(data))
		query = query+ ")"

	if len(language)>0:
		query = query+ " and ("
		for data in language:
			check_language.append(data)
			if data == language[-1]:
				query = query+" carers_app_language.name='%s'"%(str(data))
			else:
				query = query+" carers_app_language.name='%s' or "%(str(data))			
		query = query+ ")"

	if len(expertise)>0:
		query = query+ " and ("
		for data in expertise:
			check_expertise.append(data)
			if data == expertise[-1]:
				query = query+" carers_app_conditionexpertise.name='%s' "%(str(data))
			else:
				query = query+" carers_app_conditionexpertise.name='%s' or "%(str(data))
		query = query+ ")"

	list1 = []
	b = User.objects.raw(query)
	for i in b:
		list1.append(i)
	try:
		date1 = request.GET['startdate']
		start_date = datetime.datetime.strptime(str(date1), "%d-%m-%Y").date()
	except:
		start_date = ''

	try:
		date2 = request.GET['enddate']	
		end_date = datetime.datetime.strptime(str(date2), "%d-%m-%Y").date()
	except:
		end_date = ''
		
	try:
		caretype = request.GET['caretype']
	except:
		caretype = ''

	if caretype == "Hourly" and str(end_date) != '' and str(start_date) != '':
		date_list1 = []
		date_list = end_date-start_date
		for i in range(date_list.days + 1):
			date_list1.append(start_date + datetime.timedelta(days=i))
		event_start = []
		event_end = []
		for date in date_list1:
			if 'Ongoing_calendar'  in request.GET:
				for item in dict(request.GET)['Ongoing_calendar']:
					start_time = time_dict[str(item)].split('to')[0]
					end_time = time_dict[str(item)].split('to')[-1]	
					if 'am' in start_time:
						s_time = start_time.split('am')[0]
					if 'pm' in start_time:
						s_time = start_time.split('pm')[0]
					s_time = s_time.strip()
					starttime = datetime.datetime.strptime(s_time, '%H:%M').time()
					if 'am' in end_time:
						e_time = end_time.split('am')[0]
					if 'pm' in end_time:
						e_time = end_time.split('pm')[0]
					e_time = e_time.strip()
					endtime = datetime.datetime.strptime(e_time, '%H:%M').time()
					event_start.append(datetime.datetime.combine(date, starttime)) 
					event_end.append(datetime.datetime.combine(date, endtime))
		for i in range(len(event_start)):
			calendar_object = CalendarEvent.objects.filter(event_start=str(event_start[i]), event_end=str(event_end[i]))
			
			for i in calendar_object:
				if i.service_provider in list1:
					list1.remove(i.service_provider)
	if caretype == "Live In" and str(end_date) != '':	
		if start_date != '':
			caretype = CareType.objects.get(id=3)
			contract = Contract.objects.filter(caretype=caretype, service_type="Fixed", start_date=start_date, end_date=end_date)
			for item in contract:
				if i.provider in list1:
						list1.remove(i.provider)
						
	if caretype == "Over Night" and str(end_date) != '':
		if start_date != '':
			caretype = CareType.objects.get(id=2)
			contract = Contract.objects.filter(caretype=caretype, service_type="Fixed", start_date=start_date, end_date=end_date)
			for item in contract:
				if i.provider in list1:
						list1.remove(i.provider)

	if caretype == "Over Night" and str(end_date) == '':
		if start_date != '':
			caretype = CareType.objects.get(id=2)
			contract = Contract.objects.filter(caretype=caretype, service_type="Ongoing", start_date__gte=start_date)
			for item in contract:
				if i.provider in list1:
						list1.remove(i.provider)

	if caretype == "Live In" and str(end_date) == '':
		if start_date != '':
			caretype = CareType.objects.get(id=3)
			contract = Contract.objects.filter(caretype=caretype, service_type="Ongoing", start_date__gte=start_date)
			for item in contract:
				if i.provider in list1:
						list1.remove(i.provider)
						
	if caretype == "Hourly" and str(end_date) == '':
		if start_date != '':
			caretype = CareType.objects.get(id=1)
			contract = Contract.objects.filter(caretype=caretype, service_type="Ongoing", start_date__gte=start_date)
			for item in contract:
				if i.provider in list1:
						list1.remove(i.provider)
		
	count = len(list1)
	paginator = Paginator(list1, 10) 
	page = request.GET.get('page')
	try:
		list1 = paginator.page(page)
	except PageNotAnInteger:
		# If page is not an integer, deliver first page.
		list1 = paginator.page(1)
	except EmptyPage:
		# If page is out of range (e.g. 9999), deliver last page of results.
		list1= paginator.page(paginator.num_pages)
	language_list = Language.objects.filter(is_active=True)
	skill_list = Skill.objects.filter(is_active=True)
	expertise_list = ConditionExpertise.objects.filter(is_active=True)
	group = ''
	try:
		group = UserGroup.objects.get(user = request.user).name	
	except:
		pass
	
	if not request.user.is_anonymous:
		group = UserGroup.objects.get(user = request.user).name		
		notification = Notification.objects.filter(user=request.user, is_read=False)
		notification_count = notification.count()
		mssg = UserChat.objects.filter(receiver=request.user, is_read=False)
		mssg_count = mssg.count()
		return render(request, 'templates/seeker/advance_search_list.html', {'list': list1,
												'language_list': language_list,
												'skill_list': skill_list,
												'expertise_list': expertise_list,
												'group': group,
												'count': count,
												'gender': gender,
												'caretype': caretype,
												'language_list': language_list,
												'skill_list': skill_list,
												'notification': notification,
												'notification_count': notification_count,
												'mssg': mssg,
												'mssg_count': mssg_count,
												'check_expertise':check_expertise,
												'check_language':check_language,
												'check_skill':check_skill,})

	return render(request, 'templates/advance_search_list.html', {'list': list1,
												'language_list': language_list,
												'skill_list': skill_list,
												'gender': gender,
												'caretype': caretype,
												'group': group,
												'expertise_list': expertise_list,
												'count': count,
												'check_expertise':check_expertise,
												'check_language':check_language,
												'check_skill':check_skill,})


	# return render(request, "templates/advance_search.html", {})


class AdminPayment(View):
	global available_apps

	
	available_apps = [{'app_url': u'/admin/auth/', 'models': [{'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/auth/group/', 'object_name': 'Group', 'name': u'Groups', 'add_url': u'/admin/auth/group/add/'}], 'has_module_perms': True, 'name': u'Authentication and Authorization', 'app_label': 'auth'}, {'app_url': u'/admin/carers_app/', 'models': [{'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/admin_message/', 'object_name': 'Admin_Message', 'name': u'Admin_ messages'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/banner/', 'object_name': 'Banner', 'name': u'Banners', 'add_url': u'/admin/carers_app/banner/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/blog_category/', 'object_name': 'Blog_Category', 'name': u'Blog_ categorys', 'add_url': u'/admin/carers_app/blog_category/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/blog/', 'object_name': 'Blog', 'name': u'Blogs', 'add_url': u'/admin/carers_app/blog/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/calendarevent/', 'object_name': 'CalendarEvent', 'name': u'Calendar events', 'add_url': u'/admin/carers_app/calendarevent/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/cardtype/', 'object_name': 'CardType', 'name': u'Card types', 'add_url': u'/admin/carers_app/cardtype/add/'}, {'perms': {u'add': False, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/caretype/', 'object_name': 'CareType', 'name': u'Care types'}, {'perms': {u'add': True, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/cmspages/', 'object_name': 'CMSPages', 'name': u'Cms pagess', 'add_url': u'/admin/carers_app/cmspages/add/'}, {'perms': {u'add': False, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/commissionmanagement/', 'object_name': 'CommissionManagement', 'name': u'Commission managements'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/conditionexpertise/', 'object_name': 'ConditionExpertise', 'name': u'Condition expertises', 'add_url': u'/admin/carers_app/conditionexpertise/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/contractcalendar/', 'object_name': 'ContractCalendar', 'name': u'Contract calendars'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/contractcommission/', 'object_name': 'ContractCommission', 'name': u'Contract commissions'}, {'perms': {u'add': False, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/contract/', 'object_name': 'Contract', 'name': u'Contracts'}, {'perms': {u'add': True, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/emailtemplate/', 'object_name': 'EmailTemplate', 'name': u'Email templates', 'add_url': u'/admin/carers_app/emailtemplate/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/helpmessage/', 'object_name': 'HelpMessage', 'name': u'Help messages'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/interest/', 'object_name': 'Interest', 'name': u'Interests', 'add_url': u'/admin/carers_app/interest/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/invoice/', 'object_name': 'Invoice', 'name': u'Invoices'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/language/', 'object_name': 'Language', 'name': u'Languages', 'add_url': u'/admin/carers_app/language/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/notification/', 'object_name': 'Notification', 'name': u'Notifications'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/payment/', 'object_name': 'Payment', 'name': u'Payments'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/providerpaymentdetails/', 'object_name': 'ProviderPaymentDetails', 'name': u'Provider payment detailss', 'add_url': u'/admin/carers_app/providerpaymentdetails/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/skill/', 'object_name': 'Skill', 'name': u'Skills', 'add_url': u'/admin/carers_app/skill/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/useralert/', 'object_name': 'UserAlert', 'name': u'User alerts', 'add_url': u'/admin/carers_app/useralert/add/'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/usercard/', 'object_name': 'UserCard', 'name': u'User cards', 'add_url': u'/admin/carers_app/usercard/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/userdocument/', 'object_name': 'UserDocument', 'name': u'User documents'}, {'perms': {u'add': True, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/user_caretype/', 'object_name': 'User_CareType', 'name': u'User_ care types', 'add_url': u'/admin/carers_app/user_caretype/add/'}, {'perms': {u'add': False, u'change': True, u'delete': True}, 'admin_url': u'/admin/carers_app/user_skill/', 'object_name': 'User_Skill', 'name': u'User_ skills'}, {'perms': {u'add': False, u'change': True, u'delete': False}, 'admin_url': u'/admin/carers_app/user/', 'object_name': 'User', 'name': u'Users'}], 'has_module_perms': True, 'name': 'Carers_App', 'app_label': 'carers_app'}]
	def post(self,request):
		contract_id = request.POST['contract_id']
		payment = Payment.objects.get(pk=contract_id)
		stripe.api_key = settings.SECRET_STRIPE_KEY


		# Changes by pavan sharma 28/06/2018

		if payment.payment_state == "Paid" or payment.payment_state == "Cancel":
			messages.add_message(request, messages.INFO, "Request status has been changed.Please Refresh your page.")
			return HttpResponseRedirect('/admin/carers_app/payment/')

		# 28/05/2018  Convert in cent
		amount = float(request.POST['amount'])*100


		# Get stripe merchant account balance
		available_list = stripe.Balance.retrieve()['available']
		available_amount = 00.00
		for dic in available_list:
			if dic['currency'] == 'gbp':
				available_amount = dic['amount']
		available_amount = float(available_amount)/100.00


		if payment.request_state == "Ask For Release":
			if float(payment.contract.total_cost) < float(request.POST['amount']):
				messages.add_message(request, messages.INFO, "You can't release more than contract cost.")
				return HttpResponseRedirect('/admin/carers_app/payment/')

			if float(payment.contract.total_cost) > float(request.POST['amount']):
				try:
					refund = Payment.objects.get(contract=payment.contract, request_state=dict(PAYMENT_REQUEST_CHOICES).get('Ask For Refund'), payment_state=dict(PAYMENT_CHOICES).get('Paid'))
					total_amount = refund.actual_refund
					available_release_amount = payment.contract.total_cost - total_amount
					if float(request.POST['amount']) > float(available_release_amount):
						messages.add_message(request, messages.INFO, "You can't release such amount.")
						return HttpResponseRedirect('/admin/carers_app/payment/')
				except:
					pass
			if float(payment.ask_refund) < float(request.POST['amount']):
					messages.add_message(request, messages.INFO, "You can't release amount more than released amount.")
					return HttpResponseRedirect('/admin/carers_app/payment/')

			destination = payment.contract.provider.stripe_id
			if payment.contract.contract_commission > 0:
				commission = payment.contract.contract_commission
			else:
				commission = CommissionManagement.objects.get(id=1).commission

			released_amount = (amount*100)/(int(commission)+100.0)

			# Convert amount cent to actual amount
			releasedamount1 = released_amount/100
			if available_amount == float(00.00) or available_amount < releasedamount1:
				messages.add_message(request, messages.INFO, "Insufficient funds in Stripe account")
				return HttpResponseRedirect('/admin/carers_app/payment/')

			idempotency_key_stripe = request.POST['stripe_Idempotent']
			transfer_id = ''
			try:	
				transfer_id = stripe.Transfer.create(
				  amount=int(released_amount),
				  currency="gbp",
				  destination=str(destination),
				  transfer_group="{ORDER10}",
				  idempotency_key=idempotency_key_stripe
				)
			except Exception as e:
				if "idempotent" in str(e):
					messages.add_message(request, messages.INFO, "Payment already done.")
				else:
					messages.add_message(request, messages.INFO, "Insufficient funds in Stripe account")
				return HttpResponseRedirect('/admin/carers_app/payment/')

			try:
				mssg = ''
				# Contract commission
				payment.payment_state = dict(PAYMENT_CHOICES).get('Paid')
				payment.invoice.status = dict(STATUS_CHOICES).get('4')
				admincommission = float(request.POST['amount']) - float(releasedamount1)
				contract_obj = Contract.objects.get(id = payment.contract.id)
				if Payment.objects.filter(user_id = contract_obj.seeker_id, contract_id = contract_obj.id, request_state = "Service Received").exists() is False:
					if float(payment.contract.total_cost) != float(request.POST['amount']):
						seekeramount = float(payment.contract.total_cost) - float(request.POST['amount'])
						invoice = Invoice.objects.get(contract = contract_obj)
						if Payment.objects.filter(user_id = contract_obj.seeker_id, contract_id = contract_obj.id,  request_state = "Ask For Refund").exists() is False:
							if Payment.objects.filter(user_id = contract_obj.seeker_id, contract_id = contract_obj.id, request_state = "", payment_state= "Paid").exists() == False:
								paymentobj = Payment(contract=contract_obj, invoice=invoice )
								paymentobj.payment_state = dict(PAYMENT_CHOICES).get('Pending')
								paymentobj.user = contract_obj.seeker
								paymentobj.ask_refund = seekeramount
								# paymentobj.mssg = ""
								paymentobj.request_state = "Ask For Refund"
								paymentobj.save()
								contract_obj.ask_for_refund = True
								contract_obj.cancelled_by = 1
					else:
						contract_obj.status = "Completed"
				else:
					contract_obj.status = "Completed"

				payment.request_state = "Service Received"
				payment.mssg = 'Payment for service'
				update_invoice = Invoice.objects.get(contract_id=payment.contract.id)
				update_invoice.status = dict(STATUS_CHOICES).get('4')
				releasedamount2 = float(contract_obj.total_cost) - int(commission)
				if releasedamount2 == float(request.POST['amount']):
					update_invoice.invoice_status = 'Fully Released'
				elif releasedamount2 > float(request.POST['amount']):
					update_invoice.invoice_status = 'Partially Released'

				update_invoice.save()


				contract_commission = ContractCommission()
				contract_commission.contract_id = contract_obj.id
				contract_commission.commission_get = admincommission
				contract_commission.released_amount = releasedamount1
				# contract_commission.save()
				# End contract commission


				payment.actual_refund = releasedamount1
				payment.invoice.actual_refund = releasedamount1

				payment.save()
				contract_obj.save()
				contract_commission.save()

				# Notification
				content = "Your release request sucessfully processed by Carer Direct for contract "+ str(payment.contract.name)+ " and released amount is : " +str(float(request.POST['amount']))
				notification = Notification(content=content, notification_type="user_payment", user=payment.contract.provider)
				notification.save()

				# Mail Shoot

				subject = 'Carers Direct : Release Payment'
				message_type = "Release Payment"
				email = str(payment.contract.provider.email)
				contract_name = payment.contract.name

				push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)

				messages.add_message(request, messages.INFO, "Successfully Released")
				return HttpResponseRedirect('/admin/carers_app/payment/')

			except Exception, e:
				mssg = e.message
				logging.error('login error >>>>>>>>>>>>>> '+str(e))
				messages.add_message(request, messages.INFO, mssg)
				return HttpResponseRedirect('/admin/carers_app/payment/')

				# Code by pavan sharma 25/05/2018
				# if transfer_id != '':
				# 	transfer = stripe.Transfer.retrieve(str(transfer_id['id']))
				# 	re = transfer.reversals.create()
				# pass


		if payment.request_state == "Ask For Refund":

			amount = float(request.POST['amount'])*100
			idempotency_key_stripe = request.POST['stripe_Idempotent']
			# change by pavan sharma 28/06/2018
			
			amount1 = amount / 100
			if available_amount == float(00.00) or available_amount<amount1:
				messages.add_message(request, messages.INFO, "Insufficient funds in Stripe account")
				return HttpResponseRedirect('/admin/carers_app/seekerpayment/')
			
			if float(payment.contract.total_cost) < float(request.POST['amount']):
				messages.add_message(request, messages.INFO, "You can't refund more than contract cost.")
				return HttpResponseRedirect('/admin/carers_app/seekerpayment/')

			if float(payment.contract.total_cost) > float(request.POST['amount']):
				try:
					release = ContractCommission.objects.get(contract=payment.contract)
					total_amount = release.commission_get + release.released_amount
					available_refundable_amount = payment.contract.total_cost - total_amount
					if float(request.POST['amount']) > float(available_refundable_amount):
						messages.add_message(request, messages.INFO, "You can't refund such amount.")
						return HttpResponseRedirect('/admin/carers_app/payment/')
				except Exception as e:
					logging.error('login error You can>>>>>>>>>>>>>> '+str(e))
					pass

			if float(payment.ask_refund) < float(request.POST['amount']):
				messages.add_message(request, messages.INFO, "You can't refund amount more than refunded amount.")
				return HttpResponseRedirect('/admin/carers_app/payment/')
			
			# Changes made by pavan sharma 28/06/2018
			amountrelease = amount
			if float(payment.contract.total_cost) != float(request.POST['amount']):
				try:
					refund = stripe.Refund.create(
						charge=str(payment.contract.payment_id),
						amount=int(amountrelease),
						idempotency_key=idempotency_key_stripe
					)
				except Exception as e:
					if "idempotent" in str(e):
						messages.add_message(request, messages.INFO, "Payment already done.")
					else:
						mssg = e.message
						logging.error('login error refund create >>>>>>>>>>>>>> ' + str(e))
						messages.add_message(request, messages.INFO, mssg)
					return HttpResponseRedirect('/admin/carers_app/seekerpayment/')
			else:
				try:
					stripe_response = stripe.Refund.create(
						charge=str(payment.contract.payment_id),
						idempotency_key=idempotency_key_stripe
					)
				except Exception as e:
					if "idempotent" in str(e):
						messages.add_message(request, messages.INFO, "Payment already done.")
					else:
						mssg = e.message
						logging.error('login error refund create >>>>>>>>>>>>>> ' + str(e))
						messages.add_message(request, messages.INFO, mssg)
					return HttpResponseRedirect('/admin/carers_app/seekerpayment/')


			payment.payment_state = dict(PAYMENT_CHOICES).get('Paid')
			if float(request.POST['amount']) == payment.ask_refund:
				payment.invoice.status = dict(STATUS_CHOICES).get('3')
			elif float(request.POST['amount']) < payment.ask_refund:
				payment.invoice.status = dict(STATUS_CHOICES).get('2')

			#change by pavan sharma 04/09/2018
			contract_obj = Contract.objects.get(id = payment.contract.id)
			if Payment.objects.filter(user_id = contract_obj.provider_id, contract_id = contract_obj.id, request_state = "Service Received").exists() is False:
				if float(payment.contract.total_cost) != float(request.POST['amount']):
					invoice = Invoice.objects.get(contract = contract_obj)
					if Payment.objects.filter(user_id = contract_obj.provider_id,  contract_id = contract_obj.id, request_state = "Ask For Release").exists() is False:
						if Payment.objects.filter(user_id = contract_obj.provider_id,  contract_id = contract_obj.id, payment_state= "Paid").exists()  == False:
							paymentprovideramount = float(payment.contract.total_cost) - float(request.POST['amount'])
							paymentprovider = Payment(contract=contract_obj, invoice=invoice)
							paymentprovider.payment_state = dict(PAYMENT_CHOICES).get('Pending')
							paymentprovider.user = contract_obj.provider
							paymentprovider.ask_refund = paymentprovideramount
							# paymentprovider.mssg = ""
							paymentprovider.request_state = "Ask For Release"
							paymentprovider.save()
							contract_obj.ask_for_refund = True
							contract_obj.cancelled_by = 2
				else:
					contract_obj.status = "Completed"
			else:
				contract_obj.status = "Completed"
				

			
			payment.request_state = "Service Received"
			payment.mssg = 'Amount Refunded'
			payment.actual_refund = amountrelease/100
			payment.invoice.actual_refund = amountrelease/100
			payment.save()

			update_invoice = Invoice.objects.get(contract_id=payment.contract.id)
			update_invoice.status = dict(STATUS_CHOICES).get('4')
			if float(contract_obj.total_cost) == float(payment.actual_refund):
				update_invoice.invoice_status = 'Fully Refund'
			elif float(contract_obj.total_cost) > float(payment.actual_refund):
				update_invoice.invoice_status = 'Partially Refund'
			update_invoice.actual_refund = amountrelease/100
			update_invoice.save()
			contract_obj.save()

			# Notification setting
			content = "Your refund request sucessfully processed by Carer Direct for contract "+ str(payment.contract.name)+ " and refunded amount is : " +str(float(request.POST['amount']))
			notification = Notification(content=content, notification_type="user_payment", user=payment.contract.seeker)
			notification.save()

			# Email send
			subject = 'Carers Direct : Refund Payment'
			message_type = "Refund Payment"
			email = str(payment.contract.seeker.email)
			contract_name = payment.contract.name
			try:
				push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)
			except Exception as e:
				logging.error('login error email>>>>>>>>>>>>>> '+str(e))
				pass
			messages.add_message(request, messages.INFO, "Successfully refund payment.")
			return HttpResponseRedirect('/admin/carers_app/seekerpayment/')


def NotificationCount(request):
	notification = Notification.objects.filter(user=request.user, is_read=False)
	for i in notification:
		i.is_read = True
		i.save()
	data = "done"
	return HttpResponse(data)


def MessageCount(request):
	message = UserChat.objects.filter(receiver=request.user, is_read=False)
	for i in message:
		i.is_read = True
		i.save()
	data = "done"
	return HttpResponse(data)


def AdminNotificationCount(request):
	message = Notification.objects.filter(Q(notification_type="Payment")|Q(notification_type="contract")|Q(notification_type="user_payment"), is_read=False)
	for i in message:
		i.is_read = True
		i.save()
	data = "done"
	return HttpResponse(data)


def EmailMessageNotification(request, subject, message_type, email, contract_name=None, payment=None, otp=None):
	if request.is_secure():
		link='https://'+str(request.get_host())
	else:
		link='http://'+str(request.get_host())

	ctx = {
	'url':link,
	}

	if  message_type == "Refer Friend":
		full_name = str(request.user.first_name).title()+' '+str(request.user.last_name).title()
	else:
		user = User.objects.get(email=str(email))
		if not user.is_superuser and not user.is_staff:
			full_name = str(user.first_name).title()+' '+str(user.last_name).title()
			ctx['name'] = full_name
	
	if message_type == "Payment Cancel" or message_type == "Refund Payment":
		group = UserGroup.objects.get(user=user).name
		contract = Contract.objects.get(name=str(contract_name))
		ctx['contract_name'] = contract.name
		payment = Payment.objects.get(pk=int(payment))
		ctx['reason'] = payment.cancel_reason
		amount = payment.actual_refund
		ctx['amount'] = amount
		if group == "Service Seeker":
			ctx['request_type'] = "release"

		if group == "Service Provider":
			ctx['request_type'] = "refund"

	if message_type == "Calendar Update":
		contract = Contract.objects.get(name=str(contract_name))
		ctx['contract_name'] = contract.name
		ctx['verification_code'] = otp

	if message_type == "Reject Contract" or message_type == "End Contract" or message_type == "Service Received" or message_type == "Accept Contract":
		group = UserGroup.objects.get(user=user).name
		contract = Contract.objects.get(name=str(contract_name))
		provider = str(contract.provider.first_name).title()+' '+str(contract.provider.last_name).title()
		if group == "Service Seeker" and message_type == "End Contract":  
			provider = str(contract.provider.first_name).title()+' '+str(contract.provider.last_name).title()
		if group == "Service Provider" and message_type == "End Contract":  
			provider = str(contract.seeker.first_name).title()+' '+str(contract.seeker.last_name).title()
		reason = contract.reason_for_cancellation
		ctx['provider'] = provider
		ctx['reason'] = reason
		ctx['contract_name'] = contract_name
	
	if message_type == "New Contract":
		contract = Contract.objects.get(name=str(contract_name))
		contract_name = contract.name
		name = str(contract.provider.first_name).title() + ' '+ str(contract.provider.last_name).title()
		template = EmailTemplate.objects.get(id=4)
		email_html = template.content
		
		getMessage = string.replace(email_html, '{{name}}', name) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])
		getMessage = string.replace(getMessage, '{{contract_name}}', contract_name)

		ctx = {
		'getMessage':getMessage,
		}
		
		message = get_template('templates/email_templates/booking_create.html').render(ctx)			
	elif message_type == "Reject Contract":
		template = EmailTemplate.objects.get(id=5)
		email_html = template.content
		getMessage = string.replace(email_html, '{{name}}', ctx['name']) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])
		getMessage = string.replace(getMessage, '{{reason}}', ctx['reason'])
		getMessage = string.replace(getMessage, '{{contract_name}}', ctx['contract_name'])

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/booking_reject.html').render(ctx)
	
	elif message_type == "Accept Contract":
		template = EmailTemplate.objects.get(id=2)
		email_html = template.content 
		email_html = string.replace(email_html, '{{name}}', ctx['name'])
		email_html = string.replace(email_html, '{{contract_name}}', ctx['contract_name'])
		email_html = string.replace(email_html, '{{provider}}', ctx['provider'])
		email_html = string.replace(email_html, '{{url}}', ctx['url'])
		
		ctx = {
		'getMessage':email_html,
		} 
		message = get_template('templates/email_templates/booking_accept.html').render(ctx)
	
	elif message_type == "End Contract":
		template = EmailTemplate.objects.get(id=6)
		email_html = template.content
		getMessage = string.replace(email_html, '{{name}}', ctx['name']) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])
		getMessage = string.replace(getMessage, '{{reason}}', ctx['reason'])
		getMessage = string.replace(getMessage, '{{contract_name}}', ctx['contract_name'])
		getMessage = string.replace(getMessage, '{{provider}}', ctx['provider'])

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/booking_end.html').render(ctx)

	elif message_type == "Service Received":
		template = EmailTemplate.objects.get(id=7)
		email_html = template.content
		getMessage = string.replace(email_html, '{{name}}', ctx['name']) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])
		getMessage = string.replace(getMessage, '{{contract_name}}', ctx['contract_name'])

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/service_received.html').render(ctx)

	elif message_type == "Payment Cancel":
		template = EmailTemplate.objects.get(id=8)
		email_html = template.content
		getMessage = string.replace(email_html, '{{name}}', ctx['name']) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])
		getMessage = string.replace(getMessage, '{{reason}}', ctx['reason'])
		getMessage = string.replace(getMessage, '{{request_type}}', ctx['request_type'])
		getMessage = string.replace(getMessage, '{{contract_name}}', ctx['contract_name'])

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/payment_cancel.html').render(ctx)

	elif message_type == "Release Payment":
		message = get_template('templates/email_templates/release_payment.html').render(ctx)

	elif message_type == "Refund Payment":
		template = EmailTemplate.objects.get(id=9)
		email_html = template.content
		getMessage = string.replace(email_html, '{{name}}', ctx['name']) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])
		getMessage = string.replace(getMessage, '{{amount}}', ctx['amount'])
		getMessage = string.replace(getMessage, '{{contract_name}}', ctx['contract_name'])

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/refund_payment.html').render(ctx)

	elif message_type == "Help Request":
		template = EmailTemplate.objects.get(id=10)
		email_html = template.content
		postcode = Contract.objects.get(name=str(contract_name)).post_code
		getMessage = string.replace(email_html, '{{name}}', ctx['name']) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])
		getMessage = string.replace(getMessage, '{{post_code}}', postcode)

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/help_email.html').render(ctx)	

	elif message_type == "Refer Friend":
		template = EmailTemplate.objects.get(id=11)
		email_html = template.content
		getMessage = string.replace(email_html, '{{name}}', full_name) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])
		getMessage = string.replace(getMessage, '{{site_url}}', ctx['url'])

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/refer_friend_email.html').render(ctx)
	
	elif message_type == "Calendar Update":
		message = get_template('templates/email_templates/calendar_seeker_update.html').render(ctx)
	
	elif message_type == "Update Insurance":
		template = EmailTemplate.objects.get(id=12)
		email_html = template.content
		getMessage = string.replace(email_html, '{{name}}', ctx['name']) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])
		getMessage = string.replace(getMessage, '{{day_count}}', contract_name)

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/update_insurance.html').render(ctx)
	
	elif message_type == "Update Dbs":
		template = EmailTemplate.objects.get(id=13)
		email_html = template.content
		getMessage = string.replace(email_html, '{{name}}', ctx['name']) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])
		getMessage = string.replace(getMessage, '{{day_count}}', contract_name)

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/update_insurance.html').render(ctx)
	
	elif message_type == "Admin Update Dbs":
		template = EmailTemplate.objects.get(id=14)
		email_html = template.content
		getMessage = string.replace(email_html, '{{provider}}', contract_name) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/admin_dbs_update.html').render(ctx)
	
	elif message_type == "Admin Update Insurance":
		template = EmailTemplate.objects.get(id=15)
		email_html = template.content
		getMessage = string.replace(email_html, '{{provider}}', contract_name) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/admin_insurance_update.html').render(ctx)
	
	elif message_type == "Insurance Expired":
		template = EmailTemplate.objects.get(id=16)
		email_html = template.content
		getMessage = string.replace(email_html, '{{provider}}', contract_name) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/insurance_expired.html').render(ctx)
	
	elif message_type == "Dbs Expired":
		template = EmailTemplate.objects.get(id=17)
		email_html = template.content
		getMessage = string.replace(email_html, '{{provider}}', contract_name) 
		getMessage = string.replace(getMessage, '{{url}}', ctx['url'])

		ctx = {
		'getMessage':getMessage,
		}
		message = get_template('templates/email_templates/dbs_expired.html').render(ctx)
	else:
		pass

	try:
		msg = EmailMessage(subject, message, to= [email,], from_email= settings.EMAIL_HOST_USER)
		msg.content_subtype = "html"
		msg.send()	
	except:
		pass


def payout(request, id):
	try:
		payment = Payment.objects.get(pk=id)
		destination = payment.contract.provider.stripe_id
		released_amount = float(payment.actual_refund) * 100

		stripe_response = stripe.Payout.create(
		amount=int(released_amount),
		currency="gbp",
		stripe_account=str(destination),
		)
		messages.add_message(request, messages.INFO, "Payout successfully done.")
		return HttpResponseRedirect('/admin/carers_app/payment/')
	except Exception, e:
		print ">>>>>>>>>>>>>>",e
		messages.add_message(request, messages.INFO, "No balance in stripe account.")
		return HttpResponseRedirect('/admin/carers_app/payment/')


def CancelPayment(request):
	if request.method=="POST":
		payment = Payment.objects.get(pk=int(request.POST['payment_id']))

		# Changes by pavan sharma 28/06/2018

		if payment.payment_state == "Paid" or payment.payment_state == "Cancel":
			messages.add_message(request, messages.INFO, "Please Refresh your page.")
			return HttpResponseRedirect('/admin/carers_app/payment/')


		if 'payout' in request.POST:
			if request.POST['payout'] == "0":
				payment.paid_amount_by_admin = request.POST['return_amount']
				payment.cancel_status = 'Payout'
			else:
				payment.paid_amount_by_admin = request.POST['return_amount']
				payment.cancel_status = 'Refund'
		else:
			payment.cancel_status = 'Cancel'

		payment.cancel_reason = str(request.POST['cancel_reason']) 
		payment.payment_state = dict(PAYMENT_CHOICES).get('Cancel')
		payment.save()

		subject = 'Carers Direct : Payment Cancel'
		message_type = "Payment Cancel"
		contract_name = payment.contract.name
		payment = payment.id

		payment = Payment.objects.get(pk=int(payment))
		if payment.request_state == "Ask For Release":

			email = str(payment.contract.seeker.email)
			content = "Your release request cancelled by Carer Direct for contract "+ str(payment.contract.name)+ " and reason for cancellation is : " +str(request.POST['cancel_reason'])
			notification = Notification(content=content, notification_type="user_payment", user=payment.contract.provider)
			notification.save()

		if payment.request_state == "Ask For Refund":
			email = str(payment.contract.provider.email)
			content = "Your refund request cancelled by Carer Direct for contract "+ str(payment.contract.name)+ " and reason for cancellation is : " +str(request.POST['cancel_reason'])
			notification = Notification(content=content, notification_type="user_payment", user=payment.contract.provider)
			notification.save()

		push_email = EmailMessageNotification(request, subject, message_type, email, contract_name, payment.id)

	return HttpResponseRedirect('/admin/carers_app/payment/')

def payment_update_scheduler(request):
	today = datetime.datetime.today().date()
	stripe.api_key = settings.SECRET_STRIPE_KEY
	users = User.objects.filter(stripe_id__isnull=False,payment_id__isnull=True)
	for user in users:
		customer_id = user.stripe_id
		stripe_id = False
		try:
			stripe_method_id = stripe.Customer.retrieve(str(customer_id))
			stripe_id = stripe_method_id['id']
 			payment_method = stripe.PaymentMethod.list(customer=customer_id, type='card')
 			payment_id = payment_method['data'][0]['id']
 			user.payment_id = payment_id
 			user.save()
		except Exception as e:
			pass
	
	return JsonResponse("Done", safe=False)

def update_charge(request):
	stripe.api_key = settings.SECRET_STRIPE_KEY
	contracts = Contract.objects.filter(payment_id__isnull=False, payment_id__istartswith='pi')
	payments = Payment.objects.filter(stripe_payment_id__isnull=False, stripe_payment_id__istartswith='pi')
	for payment in payments:
		if payment.contract.payment_id:
			payment.stripe_payment_id = payment.contract.payment_id
			payment.save()
	
# 	for contract in contracts:
# 		print "@@@@@@@@@@@@@@", contract
# 		payment_id = contract.payment_id
# 		try:
# 			payment_intent = stripe.PaymentIntent.retrieve(str(payment_id))
#  			charge_id= payment_intent['charges']['data'][0]['id']
# 			print "charge===================", charge_id
# 			contract.payment_id = charge_id
#  			contract.save()
# 		except Exception as e:
# 			print "exception message=============", e
# 			pass
		
	return JsonResponse("Done", safe=False)

def scheduler(request):
	today = datetime.datetime.today().date()
	due_date = today+datetime.timedelta(days=7)
	contract = Contract.objects.filter(service_type="Ongoing", status="Confirmed")
	for contract_obj in contract:

		# Code by pavan sharma
		# 25/05/2018
		# pay for next seven days

		difference = str(today - contract_obj.updated.date()).split(' ')[0]
		if difference == str(7):
			# Deposit for next 7 days
			try:
				stripe.api_key = settings.SECRET_STRIPE_KEY
				customer = contract_obj.seeker.stripe_id
				stripe_account = contract_obj.provider.stripe_id
				amount = float(contract_obj.total_cost)*100
				payment_id = User.objects.get(username=contract_obj.seeker).payment_id
				payout = stripe.PaymentIntent.create(
					  amount=int(amount),
					  currency="gbp",
					  customer=customer,
					  payment_method=payment_id,
					  off_session=True,
				      confirm=True,
				      description="Contract Deposit for : " + contract_obj.name
					)
				payment_intent = stripe.PaymentIntent.retrieve(str(payout["id"]))
				charge_id= payment_intent['charges']['data'][0]['id']
# 				payout = stripe.Charge.create(
# 				  amount=int(amount),
# 				  currency="gbp",
# 				  customer=customer,
# 				  description="Contract Deposit for : " + contract_obj.name
# 				)

				# Save charge id to contract for future aspect 
				contract_obj.payment_id = charge_id
				contract_obj.save()

				invoice = Invoice.objects.filter(contract=contract_obj).order_by('-id')[0]
				invoice.status = dict(STATUS_CHOICES).get('4')
				invoice.save()

				invoice = Invoices(description=contract_obj.duties, contract=contract_obj, send_date=today, due_date=due_date, subtotal=contract_obj.total_cost, total=contract_obj.total_cost)
				invoice.save()
				invoice_name = "INV00"+str(invoice.id)
				invoice.name = invoice_name
				invoice.save()

				# Payout to provider for next 7 days
				if contract_obj.contract_commission > 0:
					commission = contract_obj.contract_commission
				else:
					commission = CommissionManagement.objects.get(id=1).commission
				amount = float(contract_obj.total_cost)*100
				# Calculate release amount

				released_amount = (amount*100)/(int(commission)+100.0)

				released_amount = float(released_amount)/100

				commission = float(contract_obj.total_cost) - released_amount

				
				# Calendar for next 7 days
				contract_calendar = ContractCalendar.objects.filter(contract_id=contract_obj)
				count = contract_calendar.count()
				contract_calendar = contract_calendar[count-7:]

				# Changes by pavan sharma 25/08/2018

				contract_calendar = list(contract_calendar)
				date = contract_calendar[-1].event_start.date()+timedelta(1)

				for calendar_seq in contract_calendar:					
					event_start = datetime.datetime.combine(date, calendar_seq.event_start.time()) 
					event_end = datetime.datetime.combine(date, calendar_seq.event_end.time())
					contract_calendar = ContractCalendar(service_provider=calendar_seq.service_provider, event_start=event_start, event_end=event_end, contract_id=contract_obj, status=calendar_seq.status, event=calendar_seq.event)
					contract_calendar.save()
					date = date+timedelta(1)
				
				mssg = "Deposit for Contract"
				payment = Payment(contract=contract_obj, invoice=invoice, )
				payment.payment_state = dict(PAYMENT_CHOICES).get('Paid')
				payment.mssg = mssg
				payment.user = contract_obj.seeker
				payment.actual_refund = released_amount
				payment.request_state = dict(PAYMENT_REQUEST_CHOICES).get('Deposit')
				payment.save()

				mssg = "Payment for service."
				payment = Payment(contract=contract_obj, invoice=invoice, )
				payment.payment_state = dict(PAYMENT_CHOICES).get('Pending')
				payment.mssg = mssg
				payment.actual_refund = released_amount
				payment.user = contract_obj.provider
				payment.request_state = dict(PAYMENT_REQUEST_CHOICES).get("Service Received")
				payment.save()
			except Exception as e:
				print "getting error  while charge creating time", e
				pass
	
	return JsonResponse("Done", safe=False)


def paidprovider(request):
	today = datetime.datetime.today().date()
	payments = Payment.objects.filter(payment_state="Pending", request_state="Service Received")
	for payment in payments:


		# Changes by  pavan sharma
		# 25/05/2018
		# pay for next seven days

		difference = str(today - payment.updated.date()).split(' ')[0]
		if difference == str(7):
			stripe.api_key = settings.SECRET_STRIPE_KEY
			destination = payment.contract.provider.stripe_id

			if payment.contract.contract_commission > 0:
				commission = payment.contract.contract_commission
			else:
				commission = CommissionManagement.objects.get(id=1).commission

			# commission = (float(payment.contract.total_cost)*float(commission))/100.00
			# amount = float(payment.contract.total_cost) - commission*100.0
			# released_amount = amount/100.00


			# Pavan sharma 25/05/2018
			available_list = stripe.Balance.retrieve()['available']
			available_amount = 00.00
			for dic in available_list:
				if dic['currency'] == 'gbp':
					available_amount = dic['amount']
			available_amount = float(available_amount)/100.00
			amount = float(payment.contract.total_cost) * 100

			# Calculate release amount
			released_amount = (amount*100)/(int(commission)+100.0)
			releasedamount1 = released_amount/100
			if available_amount == float(00.00) or available_amount < releasedamount1:
				messages.add_message(request, messages.INFO, "Insufficient funds in Stripe account")
				return JsonResponse("Insufficent Amount", safe=False)

			try:	
				transfer_id = stripe.Transfer.create(
					amount=int(released_amount),
					currency="gbp",
					destination=str(destination),
					transfer_group="{ORDER10}"
				)

				# stripe_response = stripe.Payout.create(
				# 	amount=int(released_amount),
				# 	currency="gbp",
				# 	stripe_account=str(destination),
				# )

				# mssg = stripe_response
				# Convert amount cent to actual amount
				released_amount = released_amount / 100

				# Calculate admin commission
				admincommission = float(payment.contract.total_cost)  - float(released_amount)

				payment.payment_state = dict(PAYMENT_CHOICES).get('Paid')
				
				payment.invoice.status = dict(STATUS_CHOICES).get('4')
				
				# payment.contract.status = "Released"
				payment.actual_refund = released_amount
				payment.invoice.actual_refund = released_amount
				payment.save()

				contract_commission = ContractCommission()
				contract_commission.contract = payment.contract
				contract_commission.commission_get = admincommission
				contract_commission.released_amount = released_amount
				contract_commission.save()

				print "check scheduler2 -- release payment"
				content = "Payment recieved for "+ str(payment.contract.name) + " from "+ str(payment.contract.seeker.first_name)+ ' '+ str(payment.contract.seeker.last_name)
				notification = Notification(notification_type="user_payment", content=content, user=payment.contract.provider)
				notification.save()
				
				content = "Payment recieved for "+ str(payment.contract.name) + " from "+ str(payment.contract.seeker.first_name)+ ' '+ str(payment.contract.seeker.last_name) 
				notification = Notification(notification_type="Payment", content=content, user=contract_obj.provider)
				notification.save()
			except:
				pass
				print "something went wrong while creating payout money."

	return JsonResponse("Done", safe=False)


def Need_help_address(request):
	duty = ''
	contract_id = request.GET['id']
	try:
		get_contract_detail = Contract.objects.get(id=contract_id)
	except:
		get_contract_detail = ''

	get_contract_duties = ContractDuties.objects.filter(contract = contract_id)
	if get_contract_duties:
		for duites in  get_contract_duties:
			duty += str(duites) + ','
	context_address = {
	'address' :get_contract_detail.line1 +' '+ get_contract_detail.line2,
	'city':get_contract_detail.city, 
	'post_code':get_contract_detail.post_code,
	'duty' :duty.rstrip(',')
	}
	return JsonResponse({'address':context_address})


def print_seeker_invoice(request, id):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')

	joinduites = ''
	contract_id = id
	invoice_detail = Invoice.objects.get(pk= int(contract_id))
	if invoice_detail.contract.duties:
		splitduties = eval(invoice_detail.contract.duties)
		for d in splitduties:
			joinduites += str(d)+ ','
	else:
		joinduites = ''
	billing = invoice_detail
	joinduites =joinduites.rstrip(',')
	user = User.objects.get(username=request.user)
	payments = Payment.objects.filter(invoice=id,contract=billing.contract)
	refunded_amount = 0.00
	paid_amount = 0.00
	commission_amount = 0.00
	total_amount = 0.00
	ask_refund_note = ''
	commission_obj = ContractCommission.objects.filter(contract=payments[0].contract)
	commission_amount = 0.00
	if commission_obj:
		commission_amount = commission_obj[0].commission_get
	for payment in payments:
		if payment.request_state == 'Ask For Refund' or payment.mssg == 'Amount Refunded':
			refunded_amount = payment.actual_refund if payment.payment_state=='Paid' else 0.00
			# ask_refund_note = payment.ask_refund_note
		elif payment.request_state == 'Ask For Release' or payment.request_state == 'Service Received' or payment.mssg == 'Care Complete':
			paid_amount = float(payment.contract.total_cost) - float(refunded_amount)
	total_amount = paid_amount
	return render(request,'templates/email_templates/seekerinvoice.html', {'billing': billing,
																			'joinduites': joinduites,
																		    'payments':payments[0],
																		    'refunded_amount':refunded_amount,
																	 		'paid_amount':paid_amount,
							 												'total_amount':total_amount,
																		    'refund_reason':ask_refund_note})


def print_provider_invoice(request, id):
	if request.user.is_superuser or request.user.is_staff:
		return HttpResponseRedirect('/admin/')

	joinduites = ''
	contract_id = id
	contract_detail = Contract.objects.get(pk=int(contract_id))
	if contract_detail.duties:
		splitduties = eval(contract_detail.duties)
		for d in splitduties:
			joinduites += str(d)+ ','
	else:
		joinduites = ''
	contract = contract_detail
	joinduites =joinduites.rstrip(',')
	
	payments = Payment.objects.filter(contract=contract_detail)
	refunded_amount = 0.00
	paid_amount = 0.00
	commission_amount = 0.00
	total_amount = 0.00
	ask_release_note = ''
	commission_obj = ContractCommission.objects.filter(contract=payments[0].contract)
	commission_amount = 0.00
	if commission_obj:
		commission_amount = commission_obj[0].commission_get
	for payment in payments:
		if payment.request_state == 'Ask For Refund' or payment.mssg == 'Amount Refunded':
			refunded_amount = payment.actual_refund if payment.payment_state=='Paid' else 0.00
		elif payment.request_state == 'Ask For Release' or payment.request_state == 'Service Received' or payment.mssg == 'Care Complete':
			paid_amount = payment.actual_refund if payment.payment_state=='Paid' else 0.00
			# ask_release_note = payment.ask_release_note
	total_amount = paid_amount
	return render(request,'templates/email_templates/provderpdf.html', {'contract': contract,
																		'joinduites': joinduites,
																		'refunded_amount':refunded_amount,
																		'commission_amount':commission_amount,
																 		'paid_amount':paid_amount,
						 												'total_amount':total_amount,
																		})


def check_dbs_expire(request):
	group = UserGroup.objects.get(name="Service Provider")
	users = User.objects.filter(groups__name=str(group.name), is_active=1, publish=1, complete_profile=1)
	today = datetime.datetime.today().date()
	for user in users:
		user_doc = UserDocument.objects.get(user=user)
		insurance_expire_date = user_doc.insurance_expire_date
		dbs_expire_date = user_doc.dbs_expire_date
		if dbs_expire_date != None:
			dbs_expire_days_left = str(dbs_expire_date-today).split(' ')[0]
			if (int(dbs_expire_days_left)<=60 and int(dbs_expire_days_left)>-1) or (dbs_expire_date==today):
				if user.telephone_number:
					telephone_number = user.telephone_number
					number = telephone_number.replace(" ", "")
					message = "Dear "+str(user.first_name).title()+ " " +str(user.last_name).title() +"," +" Your dbs will expire after "+str(insurance_expire_days_left)+ " days. In order to provide continue service please update your dbs." 
					send_notification(number, message)

				subject = 'Carers Direct : Update Dbs'
				message_type = 'Update Dbs'
				email = user.email
				contract_name = dbs_expire_days_left #Total no of days left
				push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)
	
			if int(dbs_expire_days_left)<0:
				user.publish = False
				if user.telephone_number:
					telephone_number=user.telephone_number
					number = telephone_number.replace(" ", "")
					message = "Dear "+str(user.first_name).title()+ " " +str(user.last_name).title() +"," +" Your insurance has been expired. In order to provide continue service please update your dbs document." 
					send_notification(number, message)

			subject = 'Carers Direct : Dbs Expired'
			message_type = 'Dbs Expired'
			email = user.email
			contract_name = insurance_expire_days_left #Total no of days left
			push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)
		
		if insurance_expire_date != None:
			insurance_expire_days_left =  str(insurance_expire_date-today).split(' ')[0]
			if (int(insurance_expire_days_left)<=30 and int(insurance_expire_days_left)>-1) or (insurance_expire_date==today):
				if user.telephone_number:
					telephone_number=user.telephone_number
					number = telephone_number.replace(" ", "")
					message = "Dear "+str(user.first_name).title()+ " " +str(user.last_name).title() +"," +" Your insurance will expire after "+str(insurance_expire_days_left)+ " days. In order to provide continue service please update your insurance." 
					send_notification(number, message)

				subject = 'Carers Direct : Update Insurance'
				message_type = 'Update Insurance'
				email = user.email
				contract_name = insurance_expire_days_left #Total no of days left
				push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)

			if int(insurance_expire_days_left)<0:
				user.publish = False
				if user.telephone_number:
					telephone_number=user.telephone_number
					number = telephone_number.replace(" ", "")
					message = "Dear "+str(user.first_name).title()+ " " +str(user.last_name).title() +"," +" Your insurance has been expired. In order to provide continue service please update your insurance document." 
					send_notification(number, message)

				subject = 'Carers Direct : Insurance Expired'
				message_type = 'Insurance Expired'
				email = user.email
				contract_name = insurance_expire_days_left #Total no of days left
				push_email = EmailMessageNotification(request, subject, message_type, email, contract_name)
	return True


def handler404(request):
	return render(request, 'templates/errorpage/404.html')


def handler500(request):
    return render(request, 'templates/errorpage/500.html')


def csrf_failure(request, reason=""):
    ctx = {'message': 'Oops!, something went wrong'}
    return HttpResponseRedirect('/login')


def contract_information(request,id):
	service_type = "Fixed"
	start_date = "None"
	end_date = "None"
	price = ''
	duration = ''
	total_cost = ''
	extra_hours = str(0)+' '+'Hours'+', '+ str(0)+' '+'Minutes'
	if request.method == "POST":
		provider_obj = User.objects.get(pk=id)
		care = CareType.objects.get(name=str(request.POST['caretype']))

		try:
			# price = Contract.objects.filter(seeker_id=request.user.id,caretype=care,status='Completed').order_by('-added')[0].price
			price = request.POST['price']
		except:
			price = request.POST['price']
			

		try:
			date1 = request.POST['startdate']
			start_date = datetime.datetime.strptime(str(date1), "%d-%m-%Y").date()

			date2 = request.POST['enddate']
			end_date = datetime.datetime.strptime(str(date2), "%d-%m-%Y").date()
		except:
			ongoing = request.POST['ongoing']
			service_type = "Ongoing"
			date1 = request.POST['startdate']
			start_date = datetime.datetime.strptime(str(date1), "%d-%m-%Y").date()

		if service_type == "Fixed":
			new_end_date = end_date+datetime.timedelta(days=1)
			duration =  str(new_end_date - start_date).split(',')[0].split(' ')[0]

			# Calendar generation for Hourly fixed for selected days
			if int(care.id) == 3 or int(care.id) == 2:
				duration = int(duration)
				total_cost = float(price)*duration
			
			continous = False
			from datetime import timedelta
			date = start_date
			
			# Calculate cost for extra hours Over Night care
			if int(care.id) == 2:
				try:
					total_hours = 15*len(list(dict(request.POST)['Ongoing_calendar']))
					
					totalMinutes = total_hours*int(duration)
					minutesPerHour = 60
					totalHours = totalMinutes // minutesPerHour
					try:
						hour_price = Contract.objects.filter(seeker_id=request.user.id,caretype=care,status='Completed').order_by('-added')[0].price
					except:
						hour_price = User_CareType.objects.get(caretype__name="Hourly", user=provider_obj).price
					contract_price = totalHours*float(hour_price)
					remainingMinutes = totalMinutes % minutesPerHour
					if remainingMinutes>0:
						half_hour_price = float(hour_price)/minutesPerHour
						half_hour_price = remainingMinutes*half_hour_price
					else:
						half_hour_price = 0
					contract_price = contract_price+half_hour_price	
					extra_hours = str(totalHours)+' '+'Hours'+', '+ str(remainingMinutes)+' '+'Minutes'
					total_cost = total_cost+contract_price
				except:
					extra_hours = str(0)+' '+'Hours'+', '+ str(0)+' '+'Minutes'
					
			if int(care.id) == 1:
				b = 0
				for k, v in dict(request.POST).items():
					if "Datewise" in str(k):
						b += 1
				datewise = []
				for k, v in dict(request.POST).items():
					if "Datewise" in str(k):
						datekey = k.split('Datewise')[1]
						datewise.append(int(datekey)) 
				datewise_len = max(datewise) + 1
				# Calculation for Hourly care
# 				if b>0:
				if datewise_len>0:
					total_hours = 0
					total_end_hours = 0
# 					for i in range(0, b):
# 						var = 'Datewise'+ str(i)
# 						booking_days = 'day_not_included'+ str(i)
#   						day_not_included = False if dict(request.POST).get(booking_days)==None else dict(request.POST).get(booking_days)[0]
# 						if i == b-1:
# 							last_day_hours = 30*len(list(dict(request.POST)[var]))
# 							last_date = "hourly_date"+str(i)
# 							last_booked_date = request.POST[last_date]
# 								
# 							last_date = datetime.datetime.strptime(str(last_booked_date), "%d-%m-%Y").date()
# 							new_end_date = end_date+datetime.timedelta(days=1)
# 							duration =  str(new_end_date - last_date).split(',')[0].split(' ')[0]
# 							
# 							total_end_hours += last_day_hours*int(duration)
# 							break
# 						total_hours += 30*len(list(dict(request.POST)[var]))
					for i in range(0, datewise_len):
						var = 'Datewise'+ str(i)
						datewise_val = 0 if dict(request.POST).get(var)==None else len(list(dict(request.POST)[var])) 
  						if i == datewise_len-1:
  							last_day_hours = 15*datewise_val
  							last_date = "hourly_date"+str(i)
  							last_booked_date = request.POST[last_date]
  								
  							last_date = datetime.datetime.strptime(str(last_booked_date), "%d-%m-%Y").date()
  							new_end_date = end_date+datetime.timedelta(days=1)
  							duration =  str(new_end_date - last_date).split(',')[0].split(' ')[0]
  							
  							total_end_hours += last_day_hours*int(duration)
  							break
  						total_hours += 15*datewise_val
  					totalMinutes = total_hours+total_end_hours
  					minutesPerHour = 60
  					totalHours = totalMinutes // minutesPerHour
  					contract_price = totalHours*float(price)
  					remainingMinutes = totalMinutes % minutesPerHour
  					if remainingMinutes>0:
  						half_hour_price = float(price)/minutesPerHour
  						half_hour_price = remainingMinutes*half_hour_price
  					else:
  						half_hour_price = 0
  					contract_price = contract_price+half_hour_price
  					hour_duration = str(totalHours)+' '+'Hour