# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from ckeditor.fields import RichTextField
from ckeditor_uploader.fields import RichTextUploadingField

from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.core.validators import MinValueValidator 
from django.db.models import Field

# Create your models here.

class User(AbstractUser):
    contact_number = models.CharField(max_length=11,default='',verbose_name='Telephone Number',null=True, blank= True)
    telephone_number = models.CharField(max_length=11,default='',verbose_name='Mobile Number', null=True, blank= True)
    gender = models.CharField(max_length=255,blank= True,null =True)
    image = models.ImageField(upload_to='pic_folder/', default='pic_folder/None/None.png')
    dob = models.DateField(null=True,blank= True)
    brief_description = models.TextField(null=True,blank= True)
    house_no = models.CharField(max_length=255)
    street_name = models.CharField(max_length=255)
    city = models.CharField(max_length=255,null=True,blank= True)
    country = models.CharField(max_length=255,null=True,blank= True)
    post_code = models.CharField(max_length=255,null=True,blank= True)
    fb_auth_token = models.CharField(max_length=255)
    tw_auth_token = models.CharField(max_length=255)
    publish = models.BooleanField(default=False)
    publish_date = models.DateField(null=True)
    forgot_password_date = models.DateTimeField(null=True,blank= True)
    refer_id = models.CharField(max_length=255)
    stripe_id = models.CharField(max_length=255, null=True)
    interest = models.CharField(max_length=255, null=True)
    lat = models.CharField(max_length=255,blank= True,null =True)
    lng = models.CharField(max_length=255,blank= True,null =True)
    experience = models.CharField(max_length=255,blank= True,null =True)
    qualification = models.CharField(max_length=255)
    profile_complete = models.BooleanField(default=False)
    form_completed = models.CharField(max_length=255,default = '')
    payment_id = models.CharField(max_length=255, null=True, blank=True)
    def __str__(self):
    	return str(self.username)

    class Meta:
    	db_table = "auth_user"


# class Country(models.Model):
# 	name = models.CharField(max_length=25)


# class City(models.Model):
# 	country_id = models.ForeignKey(Country, on_delete=models.CASCADE)
# 	name = models.CharField(max_length=25)


class Language(models.Model):
    name = models.CharField(max_length=30,unique=True)
    is_active = models.BooleanField(default=True)

    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True) 

    def __str__(self):
        return str(self.name)


class User_Language(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    language = models.ForeignKey(Language, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True) 

    def __str__(self):
        return str('') 


class Skill(models.Model):
    name = models.CharField(max_length=30,unique=True)
    skill_type = models.CharField(max_length=30)
    is_active = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)


class User_Skill(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    skill = models.ForeignKey(Skill, on_delete=models.CASCADE)

    is_active = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str('')


class ConditionExpertise(models.Model):
    name = models.CharField(max_length=30,unique=True)

    is_active = models.BooleanField()
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)


class User_ConditionExpertise(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    expertise = models.ForeignKey(ConditionExpertise, on_delete=models.CASCADE)

    is_active = models.BooleanField()
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)    

    def __str__(self):
        return str('')


class CareType(models.Model):
    name = models.CharField(max_length=30,unique=True)
    description = models.CharField(max_length=100, null=True, blank=True)
    
    is_active = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)


class User_CareType(models.Model):
    caretype = models.ForeignKey(CareType, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    price  = models.CharField(max_length=30, null=True)
    is_active = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str('') 


CONTRACT_CHOICES = (
        ('All', 'All'),
        ('Pending', 'Pending'),
        ('Confirmed', 'Confirmed'),
        ('End Contract', 'Ended Contracts'),
        ('Completed', 'Completed'),
        ('Rejected', 'Rejected'),
    )

class Contract(models.Model):
    seeker = models.ForeignKey(User, on_delete = models.CASCADE, related_name='type1')
    provider = models.ForeignKey(User, on_delete = models.CASCADE, related_name='type2')
    other_req = models.TextField(default="No requirement" ,null=True, blank=True)
    other_info = models.TextField(default="No other Informationm" ,null=True, blank=True)
    price = models.CharField(max_length=30)
    service_type = models.CharField(max_length=30, default="Fixed")
    status = models.CharField(max_length=255, choices=CONTRACT_CHOICES, default='Pending')
    duties = models.CharField(max_length=500)
    duration = models.CharField(max_length=255, null=True,blank=True)
    start_date = models.DateField(null=True)
    end_date = models.DateField(null=True, blank=True)
    caretype = models.ForeignKey(CareType, on_delete=models.CASCADE)
    care_for = models.CharField(max_length=100, null=True)
    relation = models.CharField(max_length=255, null=True,blank=True)
    service_receiver_name = models.CharField(max_length=255, null=True)
    service_receiver_address = models.CharField(max_length=255, null=True)
    line1 = models.CharField(max_length=255, null=True)
    line2 = models.CharField(max_length=255, null=True)
    city = models.CharField(max_length=255, null=True)
    post_code = models.CharField(max_length=255, null=True)
    county = models.CharField(max_length=255, null=True)
    cancelled_by = models.IntegerField(null=True,blank=True)
    reason_for_cancellation = models.CharField(max_length=225,null=True, blank=True) 
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    extra_hours = models.CharField(max_length=100, default=0, null=True,blank=True)
    total_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    payment_id = models.CharField(max_length=255, null=True, blank=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    ask_for_refund = models.BooleanField(default=False)
    ask_for_release = models.BooleanField(default=False)
    contract_commission = models.IntegerField(default=0)
    
    def __str__(self):
        return str(self.name)


class CardType(models.Model):
    name = models.CharField(max_length=50,unique =True)
    image = models.ImageField(upload_to='card_folder/', default='card_folder/None/None.png')
    is_active = models.BooleanField()
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)


class UserCard(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    card_holder_name = models.CharField(max_length=1000)
    email = models.EmailField()
    cvv_number = models.CharField(max_length=1000)
    card_number = models.CharField(max_length=1000)
    valid_date = models.DateField()
    cardtype = models.ForeignKey(CardType, on_delete=models.CASCADE)
    is_active = models.BooleanField()
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str('')

STATUS_CHOICES = (
        ('0', 'All'),
        ('1', 'Open'),
        ('2', 'Partial Refund'),
        ('3', 'Refund'),
        ('4', 'Paid'),
    )


class Invoice(models.Model):
    contract = models.ForeignKey(Contract, on_delete=models.CASCADE)
    description = models.CharField(max_length=225, null=True)
    invoice_type = models.CharField(max_length=225, null=True,blank=True)
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    send_date = models.DateTimeField()
    due_date = models.DateTimeField()
    paid = models.BooleanField(default=False)
    payment_received_date = models.DateTimeField(null=True,blank = True)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='Open')
    ask_refund = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    actual_refund = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    name = models.CharField(max_length=255, blank=True)
    invoice_status = models.CharField(max_length=225, null=True, blank=True)

    def __str__(self):
        return str(self.description)


class UserEducation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    school = models.CharField(max_length=200)
    city = models.CharField(max_length=100)
    start_date = models.DateField()
    end_date = models.DateField()

    def __str__(self):
        return str(self.school)


class UserExperience(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    employer_name = models.CharField(max_length=100, default = '',blank= True,null =True)
    employer_phone = models.CharField(max_length=200, default = '',blank= True,null =True)
    start_date = models.DateField(null=True,blank =True)
    end_date = models.DateField(null=True,blank =True)

    def __str__(self):
        return str('')


class UserDocument(models.Model):
    user = models.ForeignKey(User, on_delete = models.CASCADE)
    dbs = models.FileField(upload_to='documents')
    insurance = models.FileField(upload_to='documents')
    driving_license = models.FileField(upload_to='documents')
    passport_photo = models.FileField(upload_to='documents')
    bank_society_statement = models.FileField(upload_to='documents')
    utility = models.FileField(upload_to='documents')
    reference1 = models.FileField(upload_to='documents',blank= True,null =True)
    reference2 = models.FileField(upload_to='documents',blank= True,null =True)
    dbs_expire_date = models.DateField(null=True, blank =True)
    insurance_expire_date = models.DateField(null=True, blank =True)

    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str('')


    def documents(self,instance, filename):
        return os.mkdir(self.documents.join(self.user.username))


class Blog_Category(models.Model):
    name = models.CharField(max_length=255,unique=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=False)

    def __str__(self):
        return str(self.name)

    def __unicode__(self):
        return self.name


class Blog(models.Model):
    title = models.CharField(max_length=255)
    content = RichTextUploadingField()
    image = models.ImageField(upload_to='blog/', default='blog/None.png')
    category = models.ForeignKey(Blog_Category, on_delete=models.CASCADE)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=False)

    def __str__(self):
        return str(self.title)


class Admin_Message(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    contact_number = models.CharField(max_length=100)
    message = models.CharField(max_length=255)
    is_read = models.BooleanField(default=False)
    is_replied = models.BooleanField(default=False)

    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    notification_type = models.CharField(max_length=100)
    is_read = models.BooleanField(default=False)
    added = models.DateTimeField(auto_now_add=True)


CALENDAR_CHOICES = (
        ('Generated', 'Generated'),
        ('Continue', 'Continue'),
        ('Addmore', 'Addmore'),
    )

class CalendarEvent(models.Model):
    service_provider = models.ForeignKey(User, on_delete=models.CASCADE)
    contract_id = models.ForeignKey(Contract, on_delete=models.CASCADE)
    event = models.CharField(max_length=255)
    event_start = models.DateTimeField()
    event_end = models.DateTimeField()
    status = models.CharField(max_length=255, choices=CALENDAR_CHOICES)
    is_active = models.BooleanField(default=True)

    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.event)


class ProviderPaymentDetails(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    bank_name = models.CharField(max_length=100)
    account_holder_name = models.CharField(max_length=100)
    account_number = models.CharField(max_length=1000)
    sort_code = models.CharField(max_length=1000)
    state = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    post_code = models.CharField(max_length=100)

    def __str__(self):
        return str(self.account_holder_name)


class Banner(models.Model):
    name = models.CharField(max_length=25,unique=True)
    image = models.ImageField(upload_to='banner_folder/', default='banner_folder/None/None.png')
    added = models.DateTimeField(auto_now_add=True)
    valid_from = models.DateField(null=True)
    valid_to = models.DateField(null=True)
    updated = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=False)

    def __str__ (self):
        return str(self.name)


class CMSPages(models.Model):
    title = models.CharField(max_length=25)
    content = RichTextUploadingField()
    is_active = models.BooleanField()
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.title)


class EmailTemplate(models.Model):
    title = models.CharField(max_length=25)
    content = RichTextField()
    is_active = models.BooleanField()
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now = True)

    def __str__(self):
        return str(self.title)


class HelpMessage(models.Model):
    contract = models.ForeignKey(Contract, on_delete=models.CASCADE)
    providers = models.CharField(max_length=50)
    accept_by = models.CharField(max_length=25)
    duties = models.CharField(max_length = 500)
    notes = models.TextField()
    added = models.DateTimeField(auto_now_add=True,verbose_name='Generated on')
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    def __unicode__(self):
        return str(self.id)


class UserAlert(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message_email_alert = models.BooleanField(default=True)
    message_system_alert = models.BooleanField(default=True)
    contract_email_alert = models.BooleanField(default=True)
    contract_system_alert = models.BooleanField(default=True)
    payment_email_alert = models.BooleanField(default=True)
    payment_system_alert = models.BooleanField(default=True)
    help_email_alert = models.BooleanField(default=True)
    help_system_alert = models.BooleanField(default=True)
    invoice_email_alert = models.BooleanField(default=True)
    invoice_system_alert = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    

class ContractCalendar(models.Model):
    service_provider = models.ForeignKey(User, on_delete=models.CASCADE)
    contract_id = models.ForeignKey(Contract, on_delete=models.CASCADE)
    event = models.CharField(max_length=255)
    event_start = models.DateTimeField()
    event_end = models.DateTimeField()
    status = models.CharField(max_length=255, choices=CALENDAR_CHOICES)
    is_active = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str('')




class ContractDuties(models.Model):
    contract = models.ForeignKey(Contract, on_delete= models.CASCADE)
    duty = models.ForeignKey(Skill, on_delete= models.CASCADE)

    def __str__(self):
        return str('')
    

PAYMENT_CHOICES = (
        ('All', 'All'),
        ('Pending', 'Pending'),
        ('Cancel', 'Cancel'),
        ('Paid', 'Paid'),
    )


PAYMENT_REQUEST_CHOICES = (
        ('All', 'All'),
        ('Deposit', 'Deposit'),
        ('Ask For Release', 'Ask For Release'),
        ('Ask For Refund', 'Ask For Refund'),
        ('Service Received', 'Service Received')
    )


class Payment(models.Model):
    contract = models.ForeignKey(Contract, on_delete=models.CASCADE)
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE)
    mssg = models.CharField(max_length=255, blank=True)
    request_type = models.CharField(max_length=255, blank=True)
    ask_refund = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    actual_refund = models.DecimalField(max_digits=10, decimal_places=2, default=0,verbose_name='Paid Amount')
    payment_state = models.CharField(max_length=255, choices=PAYMENT_CHOICES, default='Paid')
    request_state = models.CharField(max_length=255, choices=PAYMENT_REQUEST_CHOICES, default='Deposit')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    stripe_payment_id = models.CharField(max_length=255, blank=True)
    cancel_reason = models.CharField(max_length=255, blank=True)
    added = models.DateTimeField(auto_now_add=True)
    paid_amount_by_admin = models.DecimalField(max_digits=10, decimal_places=2, default=0, verbose_name='Amount')
    cancel_status = models.CharField(max_length=255, blank=True, default= '-', verbose_name='Payment Status')
    updated = models.DateTimeField(auto_now=True)
    

class qualification(models.Model):
    name = models.CharField(max_length=255,default = '',unique =True)
    is_active = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True) 

    def __str__(self):
        return str(self.name)


class userqualification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    qualification = models.ForeignKey(qualification, on_delete=models.CASCADE)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True) 

    def __str__(self):
        return str('')


class Interest(models.Model):
    name = models.CharField(max_length=255,default = '',unique =True)
    is_active = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True) 

    def __str__(self):
        return str(self.name)


class User_interest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    interest = models.ForeignKey(Interest, on_delete=models.CASCADE)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True) 

    def __str__(self):
        return str('')


class CommissionManagement(models.Model):
    commission = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "{0}".format(self.commission)


class ContractCommission(models.Model):
    contract = models.ForeignKey(Contract, on_delete=models.CASCADE)
    commission_get = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    released_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    commision_released = models.BooleanField(default=False, verbose_name='Released')
    is_active = models.BooleanField(default=True)
    is_active1 = models.BooleanField(default=True)
    is_active2 = models.BooleanField(default=True)
    added = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)


class LoginFail(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    added = models.DateTimeField(auto_now_add=True)
   

    def __str__(self):
        return str('')
