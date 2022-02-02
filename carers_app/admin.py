# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from carers_app.models import *
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from ckeditor.fields import RichTextField
from django.contrib.admin.sites import AdminSite
from django.contrib import messages
from django.views.generic.base import View
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404
from django.utils.html import format_html
from django.core.urlresolvers import reverse
from django.conf.urls import url
from datetime import datetime
import string
from django.db.models import Sum
from django.template.loader import get_template
from django.core.mail import EmailMessage
from django.contrib.auth.models import Group
import stripe
from django.db.models import Q
import sys
import csv

reload(sys)
sys.setdefaultencoding('utf8')

# Register your models here.

stripe.api_key = settings.SECRET_STRIPE_KEY

AdminSite.index_template = "templates/admin/preferences.html"
AdminSite.password_change_template = "templates/admin/password_change_form.html"
AdminSite.password_change_done_template = "templates/admin/password_change_done.html"
#AdminSite.login_template = "templates/login.html",

admin.ModelAdmin.actions_on_top = True
admin.ModelAdmin.actions_on_bottom = False

class User_Inline(admin.TabularInline):
    model = User_Language
    fk_name = "user"
    can_delete = False
    extra = 0
    verbose_name_plural = "User Language"
    # max_num = 1


class User_Skill_Inline(admin.TabularInline):
    model = User_Skill
    fk_name = "user"
    can_delete = False
    extra =0
    verbose_name_plural = "User Skill"
    # max_num = 1


class User_document_Inline(admin.TabularInline):
    model = UserDocument
    fk_name = "user"
    can_delete = False
    extra =0
    max_num = 1
    fields = ('dbs_expire_date','insurance_expire_date','user','dbs','passport_photo','insurance', 'driving_license', 'bank_society_statement', 'utility', 'reference1', 'reference2')
    verbose_name_plural = "User Document"
    

class User_exp_Inline(admin.TabularInline):
    model = UserExperience
    fk_name = "user"
    can_delete = False
    extra = 0
    max_num = 3
    verbose_name_plural = "User Experience"


class User_care_type_Inline(admin.TabularInline):
    model = User_CareType
    fk_name = "user"
    can_delete = True
    extra =0
    max_num = 0
    readonly_fields = ('caretype',)
    verbose_name_plural = "User CareType"


class User_card_type_Inline(admin.TabularInline):
    model = UserCard
    fk_name = "user"
    can_delete = False
    extra =0
    max_num = 1


class User_qualification_Inline(admin.TabularInline):
    model = userqualification
    fk_name = "user"
    can_delete = False
    extra =0
    verbose_name_plural = "User Qualification"

 
class User_Interest_Inline(admin.TabularInline):
    model = User_interest
    fk_name = "user"
    can_delete = False
    extra =0
    verbose_name_plural = "User Interest"
    # max_num = 1User_interestUser_ConditionExpertise


class User_cdnexpertinse_Inline(admin.TabularInline):
    model = User_ConditionExpertise
    fk_name = "user"
    can_delete = False
    extra =0
    verbose_name_plural = "User ConditionExpertise"
    # max_num = 1User_interestUser_ConditionExpertise


class UserAdmin(admin.ModelAdmin):

    def get_list_display(self, request):

        def address(self):
            address = ''
            group=Group.objects.get(user=self).name
            if group=="Service Seeker":
                addr = str(self.street_name).split('&line2=')
                address =  str(self.house_no)+' '+str(addr[0])+', '+str(addr[-1])+', '+str(self.country)+' '+str(self.city)+' '+str(self.post_code)
            if group=="Service Provider":
                address =  str(self.street_name)+', '+str(self.country)+' '+str(self.house_no)+' '+str(self.city)+' '+str(self.post_code)
            if 'None' in address:
                return "---"
            else:
                return address
        address.short_description = "Address"

        list_display = ['first_name','last_name','email',address,'contact_number','telephone_number' ,'fb_auth_token','tw_auth_token','is_active','publish']
        return list_display

    readonly_fields = ('username',)
    list_per_page = 10
    search_fields = ['first_name','last_name']
    
    ordering = ['date_joined']
    list_filter = ['groups', 'is_active', 'publish']
    fieldsets = (
        (None, {'fields': ('first_name','last_name','email','dob','experience','lat','lng','publish','image', 'username',
        	'contact_number','telephone_number','groups','post_code','gender', 'is_staff', 'is_superuser', 'is_active',
            'date_joined','last_login','brief_description')}),
        
    )
    ordering = ('email',)
    actions = ['DeleteUser', 'ActivateUser','PublishUser','DeactivateUser','UnPublishUser']

    
    inlines = [
        User_Inline,
        User_Skill_Inline,
        User_document_Inline,
        User_exp_Inline,
        User_care_type_Inline,
        # User_card_type_Inline,
        User_qualification_Inline,
        User_Interest_Inline,
        User_cdnexpertinse_Inline
    ]

    

    def save_model(self, request, obj, form, change):
        name = str(obj.first_name).title() +' '+ str(obj.last_name).title()
        obj.user = request.user
        obj.username = obj.email
        group = Group.objects.get(user = obj).name
        if request.is_secure():
            logo_url = 'https://'+str(request.get_host())
        else:
            logo_url = 'http://'+str(request.get_host())

        if group == "Service Provider":
            if 'userdocument_set-0-dbs_expire_date' in request.POST:
                if  request.POST['userdocument_set-0-dbs_expire_date'] != '': 
                    dbs_date = datetime.strptime(str(request.POST['userdocument_set-0-dbs_expire_date']), "%Y-%m-%d").date()
                    user_doc = UserDocument.objects.filter(user=obj)

                    if user_doc.count()>0:
                       dbs_expire = user_doc[0].dbs_expire_date

                       if dbs_date != dbs_expire :
                            document = "DBS"
                            template = EmailTemplate.objects.get(id=18)
                            email_html = template.content 
                            getMessage = string.replace(email_html, '{{url}}', logo_url)
                            getMessage = string.replace(getMessage, '{{name}}', name)
                            getMessage = string.replace(getMessage, '{{document}}', document)

                            ctx = {
                            'getMessage':getMessage,
                            }
                            email = str(obj.email) 
                            subject = 'Carers Direct : Update Document'
                            message = get_template('templates/email_templates/doc_update_template.html').render(ctx)
                            msg = EmailMessage(subject, message, to= [email], from_email= settings.EMAIL_HOST_USER)
                            msg.content_subtype = "html"
                            msg.send() 
                        # messages.add_message(request, messages.INFO, "We have successfully sent an activation link to your registered email address. Please activate your account.")
                        # return HttpResponseRedirect('/signup')
            if 'userdocument_set-0-insurance_expire_date' in request.POST:
                if  request.POST['userdocument_set-0-insurance_expire_date'] != '':
                    insurance_date = datetime.strptime(str(request.POST['userdocument_set-0-insurance_expire_date']), "%Y-%m-%d").date()
                    user_doc = UserDocument.objects.filter(user=obj)
                    
                    if user_doc.count()>0:
                       insurance_expire = user_doc[0].insurance_expire_date
                       if insurance_date != insurance_expire :
                            document = "Insurance"
                            template = EmailTemplate.objects.get(id=18)
                            email_html = template.content 
                            getMessage = string.replace(email_html, '{{url}}', logo_url)
                            getMessage = string.replace(getMessage, '{{name}}', name)
                            getMessage = string.replace(getMessage, '{{document}}', document)

                            ctx = {
                            'getMessage':getMessage,
                            } 
                            email = str(obj.email)
                            subject = 'Carers Direct : Update Document'
                            message = get_template('templates/email_templates/doc_update_template.html').render(ctx)
                            msg = EmailMessage(subject, message, to= [email], from_email= settings.EMAIL_HOST_USER)
                            msg.content_subtype = "html"
                            msg.send()
        obj.save()

    def get_actions(self, request):
        #Disable delete
        actions = super(UserAdmin, self).get_actions(request)
        del actions['delete_selected']
        return actions

    def has_delete_permission(self, request, obj=None):
        return False
        
    def has_add_permission(self, request):
        return False

    def ActivateUser(self, request, queryset):
        queryset.update(is_active=1)
        return messages.add_message(request, messages.INFO, 'User successfully activated')
        # messages.add_message(request, messages.INFO, 'Car has been sold')
    
    def PublishUser(self, request, queryset):
        queryset.update(publish=1)
        return messages.add_message(request, messages.INFO, 'User successfully published')
    
    def DeactivateUser(self, request, queryset):
        queryset.update(is_active=0)
        return messages.add_message(request, messages.INFO, 'User successfully deactivated')
    
    def UnPublishUser(self, request, queryset):
        queryset.update(publish=0)
        return messages.add_message(request, messages.INFO, 'User successfully unpublished')

    def DeleteUser(self, request, queryset):
        for user in queryset:
            if Contract.objects.filter(Q(seeker=user)|Q(provider=user)).count()>0:
                message = "Can't delete "+ str(user.first_name)+ ' '+ str(user.last_name)
            else:
                check_super_user = User.objects.filter(id = user.id , is_superuser = 1)
                if check_super_user:  
                    message = "You can't delete admin user."
                else:
                    user.delete()
                    message = "User delete successfully."
        return messages.add_message(request, messages.INFO, message)


    ActivateUser.short_description = "Activate selected user"
    DeactivateUser.short_description = "Deactivate selected user"
    PublishUser.short_description = "Publish selected user"
    UnPublishUser.short_description = "Unpublish selected user"
    DeleteUser.short_description = "Delete selected user"


admin.site.register(User, UserAdmin)


class BlogAdmin(admin.ModelAdmin):
    list_per_page = 10
    search_fields = ('title','category__name',)
    list_filter = ['category__name']
    list_display = ['title','category','image','added','updated']
# 'added','updated','is_active'


admin.site.register(Blog, BlogAdmin)

class contract_Inline(admin.TabularInline):
    model = ContractDuties
    fk_name = "contract"
    can_delete = False
    extra = 0
    max_num = 1
    readonly_fields = ('contract', 'duty')


class contract_calender_Inline(admin.TabularInline):
    model = ContractCalendar
    fk_name = "contract_id"
    can_delete = False
    extra = 0
    max_num = 1
    fields=('event_start','event_end')
    readonly_fields = ('event_start', 'event_end')


class ContractAdmin(admin.ModelAdmin):

    inlines = [
        contract_Inline,
        contract_calender_Inline
    ]


    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return True

    def save_model(self, request, obj, form, change):
        pass

    def get_readonly_fields(self, request, obj=None):
        readonly_fields = list(set(
            [field.name for field in self.opts.local_fields] +
            [field.name for field in self.opts.local_many_to_many]
        ))
        if 'is_submitted' in readonly_fields:
            readonly_fields.remove('is_submitted')
        return readonly_fields

    def get_list_display(self, request):
        def seeker(self):
            user = User.objects.get(username=self.seeker)
            return user.get_full_name().title()

        seeker.short_description = "Seeker Name"

        def provider(self):
            user = User.objects.get(username=self.provider)
            return user.get_full_name().title()

        provider.short_description = "Provider Name"

        list_display = ['name',seeker, provider,'get_status_display','total_cost', 'start_date', 'end_date', 'contract_commission' ,'account_actions']
        try:
            status = request.GET['status']
            if str(status) == "Terminated" or str(status) == "Cancelled":
                list_display.append('cancelled_by')
                list_display.append('reason_for_cancellation')
                return list_display
            else:
                 pass
            return list_display
        except:
            return list_display


    def update_to_accepted(modeladmin, request, queryset):
        return queryset.update(status="Accepted")

    update_to_accepted.short_description = "Change Status As Accepted "

    def update_to_rejected(modeladmin, request, queryset):
        return queryset.update(status="Rejected")

    update_to_rejected.short_description = "Change Status As Rejected "

    def update_to_completed(modeladmin, request, queryset):
        return queryset.update(status="Completed")

    update_to_completed.short_description = "Change Status As Completed "

    def update_to_terminated(modeladmin, request, queryset):
        return queryset.update(status="Terminated")


    def account_actions(self, obj):
        if obj.status== "Pending" or obj.status == "Confirmed":
            return format_html(
                '<a class="button" onclick="OpenContract('+str(obj.id)+' , '+str(obj.contract_commission)+')"  >Edit Comission</a>&nbsp;'
            )
    account_actions.short_description = 'Action'
    account_actions.allow_tags = True


    update_to_terminated.short_description = "Change Status As Terminated "

    list_per_page = 10
    search_fields = ('name',)
    list_filter = ['status']
    actions = ['update_to_accepted', 'update_to_rejected', 'update_to_completed','update_to_terminated']


admin.site.register(Contract, ContractAdmin)


class CMS(admin.ModelAdmin):
    list_display = ['title', 'added', 'updated']
    search_fields = ('title',)
    def get_actions(self, request):
        #Disable delete
        actions = super(CMS, self).get_actions(request)
        del actions['delete_selected']
        return actions

    def has_delete_permission(self, request, obj=None):
        return False

    # def has_add_permission(self, request):
    #     return False

    def short_description(self, request):
        pass


class Emailtemplateseetting(admin.ModelAdmin):
    list_display = ['title','added','is_active']
    search_fields = ('title',)
    def get_actions(self, request):
        actions = super(Emailtemplateseetting, self).get_actions(request)
        del actions['delete_selected']
        return actions
    def has_delete_permission(self, request, obj=None):
        return False
    def short_description(self, request):
        pass

admin.site.register(CMSPages,CMS)


admin.site.register(EmailTemplate,Emailtemplateseetting)


admin.site.register(Banner)



admin.site.register(CalendarEvent)


class InvoiceAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['contract','total','get_status_display']
    list_filter = ['status']
    search_fields = ['contract__seeker__first_name', 'contract__seeker__last_name', 'contract__provider__first_name', 'contract__provider__last_name' ]
    def has_add_permission(self, request):
        return False


admin.site.register(Invoice, InvoiceAdmin)


class PaymentAdmin(admin.ModelAdmin):

    def get_list_display(self, request):
        
        def seeker(self):
            user = Payment.objects.get(pk=self.id)
            return str(user.contract.seeker.first_name).title()+' '+str(user.contract.seeker.last_name).title()

        def provider(self):
            user = Payment.objects.get(pk=self.id)
            return str(user.contract.provider.first_name).title()+' '+str(user.contract.provider.last_name).title()
        
        def total_cost(self):
            user = Payment.objects.get(pk=self.id)
            return str(user.contract.total_cost)

        def AskRelease(self):
            user = Payment.objects.get(pk=self.id)
            return str(user.ask_refund)
        def PaymentStatus(self):
            user = Payment.objects.get(pk=self.id)
            return str(user.payment_state)

        total_cost.short_description = "Total Cost"

        provider.short_description = "Provider Name"

        AskRelease.short_description = "Release Amount"

        seeker.short_description = "Seeker Name"
        PaymentStatus.short_description = "Carried"
        # 'cancel_status', 'paid_amount_by_admin',
        list_display = ['contract',seeker, provider,'mssg','request_state', total_cost, AskRelease, 'actual_refund', PaymentStatus,'updated','cancel_reason', 'account_actions',]
        return list_display

    # Pavan Sharma 25/05/2018

    def get_queryset(self, request):
        queryset = []
        queryset1 = Payment.objects.all()
        raw_query = 'SELECT * FROM `auth_user_groups` inner join auth_group on auth_group.id = auth_user_groups.group_id'
        query = Group.objects.raw(raw_query)
        group = list(query)
        for group_user in group:
            if group_user.name == "Service Provider":
                queryset.append(int(group_user.user_id))
        queryset = queryset1.filter(user_id__in=queryset)
        return queryset

    list_display_links = None
    list_per_page = 10    
    list_filter = ['payment_state']
    search_fields = ['payment_state', 'contract__name', 'contract__seeker__first_name', 'contract__seeker__last_name', 'contract__provider__first_name', 'contract__provider__last_name']


    def get_urls(self):
        urls = super(PaymentAdmin, self).get_urls()
        return urls

    def has_add_permission(self, request):
        return False

    def account_actions(self, obj):
        # user = str(obj.id)+','+str(obj.contract.total_cost)+','+"'"+str(obj.mssg)+"'"+','+"'"+str(0)+"'"
        user = str(obj.id)+','+str(obj.contract.total_cost)+','+"'"+str(0)+"'"
        
        if obj.request_state == "Ask For Release" and obj.payment_state == "Pending":
            return format_html(
                '<a class="button" onclick="Openmodal('+str(user)+');random_key();"  >Release</a>&nbsp;'
                '<a class="button" onclick="Opencancelmodal('+str(user)+')">Cancel</a>&nbsp;',
                # '<a class="button" onclick="OpenPayoutmodel('+str(user)+')" >Payout</a>&nbsp;',
            )
        # url = "/payout/"+ str(obj.id)+'/'

        # return format_html(
        #         '<a class="button" href='+url+'>Payout</a>&nbsp;',
        #     )

        # if obj.request_state == "Ask For Refund" and obj.payment_state == "Pending":
        #     return format_html(
        #         '<a class="button" onclick="Openmodal('+str(user)+')"  >Refund</a>&nbsp;'
        #         '<a class="button" onclick="Opencancelmodal('+str(user)+')"  >Cancel</a>&nbsp;',                
        #     )


    account_actions.short_description = 'Payment Actions'
    account_actions.allow_tags = True

    def Release_Payment(self,modeladmin, request):
        for i in request:
            payment_id = i.id 
        url = "/admin/carers_app/payments/"+ str(payment_id) + "/" 
        return HttpResponseRedirect(url)

    #Release_Payment.short_description = "Release Payment"

    def Refund_Payment(self, request):
        
        return HttpResponse("HEllo")

    Refund_Payment.short_description = "Refund Payment"

    # actions = ['Release_Payment', 'Refund_Payment',]

 
# By pavan sharma
class ServiceSeekerPayment(admin.ModelAdmin):

    def get_list_display(self, request):
        
        def seeker(self):
            user = Payment.objects.get(pk=self.id)
            return str(user.contract.seeker.first_name).title()+' '+str(user.contract.seeker.last_name).title()

        seeker.short_description = "Seeker Name"

        def provider(self):
            user = Payment.objects.get(pk=self.id)
            return str(user.contract.provider.first_name).title()+' '+str(user.contract.provider.last_name).title()
        
        def total_cost(self):
            user = Payment.objects.get(pk=self.id)
            return str(user.contract.total_cost)                                                                                                                                                                                                                                                                                                                                                                                                                             

        def PaymentStatus(self):
            user = Payment.objects.get(pk=self.id)
            return str(user.payment_state)
        PaymentStatus.short_description = "Carried"
        total_cost.short_description = "Total Cost"

        provider.short_description = "Provider Name"
        # 'cancel_status', 'paid_amount_by_admin',
        list_display = ['contract',seeker, provider,'mssg','request_state', total_cost,'ask_refund', 'actual_refund', PaymentStatus,'updated','cancel_reason', 'account_actions',]
        return list_display

    # Pavan Sharma 25/05/2018
    def get_queryset(self, request):
        queryset = []
        queryset1 = Payment.objects.all()
        raw_query = 'SELECT * FROM `auth_user_groups` inner join auth_group on auth_group.id = auth_user_groups.group_id'
        query = Group.objects.raw(raw_query)
        group = list(query)
        for group_user in group:
            if group_user.name == "Service Seeker":
                queryset.append(int(group_user.user_id))
        queryset = queryset1.filter(~Q(request_state = "Ask For Release") , user_id__in=queryset)
        return queryset

    list_display_links = None
    list_per_page = 10    
    list_filter = ['payment_state']
    search_fields = ['payment_state', 'contract__name', 'contract__seeker__first_name', 'contract__seeker__last_name', 'contract__provider__first_name', 'contract__provider__last_name']

    
    def get_urls(self):
        urls = super(ServiceSeekerPayment, self).get_urls()
        return urls
    def has_add_permission(self, request):
        return False

    def account_actions(self, obj):
        user = str(obj.id)+','+str(obj.contract.total_cost)+','+"'"+str(1)+"'"
        
        # if obj.request_state == "Ask For Release" and obj.payment_state == "Pending":
        #     return format_html(
        #         '<a class="button" onclick="Openmodal('+str(user)+')"  >Release</a>&nbsp;'
        #         '<a class="button" onclick="Opencancelmodal('+str(user)+')"  >Cancel</a>&nbsp;',
        #     )

        if obj.request_state == "Ask For Refund" and obj.payment_state == "Pending":
            return format_html(
                '<a class="button" onclick="Openmodal('+str(user)+');random_key();">Refund</a>&nbsp;'
                '<a class="button" onclick="Opencancelmodal('+str(user)+')"  >Cancel</a>&nbsp;',                
            )


    account_actions.short_description = 'Payment Actions'
    account_actions.allow_tags = True

    def Release_Payment(self,modeladmin, request):
        for i in request:
            payment_id = i.id 
        url = "/admin/carers_app/payments/"+ str(payment_id) + "/" 
        return HttpResponseRedirect(url)

    #Release_Payment.short_description = "Release Payment"

    def Refund_Payment(self, request):
        
        return HttpResponse("HEllo")

    Refund_Payment.short_description = "Refund Payment"

    # actions = ['Release_Payment', 'Refund_Payment',]


class seekerpayment(Payment):
    class Meta:
        proxy = True


admin.site.register(Payment, PaymentAdmin)


admin.site.register(seekerpayment, ServiceSeekerPayment)


admin.site.register(UserAlert)


admin.ModelAdmin.change_list_template = "templates/admin/app.html"


class HelpMessageAdmin(admin.ModelAdmin):
    search_fields = ['contract__name','duties','contract__provider__first_name','contract__provider__last_name']
    fieldsets = (
        (None, {'fields': ('contract','providers','duties','notes')}),
    )
    def has_add_permission(self, request):
        return False

    def get_list_display(self, request):
        def From(self):
            user = HelpMessage.objects.get(pk=str(self))
            return str(user.contract.provider.first_name).title()+' '+str(user.contract.provider.last_name).title()

        From.short_description = "From"


        def contractid(self):
            user = HelpMessage.objects.get(pk= str(self))
            if user.contract.name:
                value = user.contract.name
            else:
                value = ''
            return str(value) 

        contractid.short_description = "contractid"
        list_display = [contractid,From,'providers','duties','notes','added']
        return list_display


admin.site.register(HelpMessage, HelpMessageAdmin)


class LanguageAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['name','added','is_active']
    list_filter = ['is_active']
    search_fields = ['name']


admin.site.register(Language, LanguageAdmin)


class SkillAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['name', 'skill_type','added','is_active']
    list_filter = ['is_active']
    search_fields = ['name']
    

admin.site.register(Skill, SkillAdmin)


class ConditionExpertiseAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['name','added',]
    list_filter = ['is_active']
    search_fields = ['name']    


admin.site.register(ConditionExpertise, ConditionExpertiseAdmin)


class CareTypeAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['name','added','is_active']
    list_filter = ['is_active']
    search_fields = ['name']
    def has_add_permission(self, request):
        return False
    def has_delete_permission(self, request, obj=None):
        return False
    def get_actions(self, request):
        actions = super(CareTypeAdmin, self).get_actions(request)
        del actions['delete_selected']
        return actions


admin.site.register(CareType, CareTypeAdmin)


class CardTypeAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['name','image','added','is_active']
    list_filter = ['is_active']
    search_fields = ['name']    


admin.site.register(CardType, CardTypeAdmin)


class User_SkillAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display_links = None
    def has_add_permission(self, request):
        return False


admin.site.register(User_Skill, User_SkillAdmin)


class UserDocumentAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['dbs_expire_date','insurance_expire_date','user','dbs','insurance', 'driving_license', 'bank_society_statement', 'utility']
    search_fields = ['user__first_name', 'user__last_name', 'user__email']
    list_display_links = None
    def has_change_permission(self, request):
        return False


admin.site.register(UserDocument, UserDocumentAdmin)


class interestAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['name','added','is_active']
    search_fields = ['name']


admin.site.register(Interest, interestAdmin)


class CommissionManagementAdmin(admin.ModelAdmin):
    list_display = ['commission','is_active']
    def has_add_permission(self, request):
        return False
    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(CommissionManagement, CommissionManagementAdmin)


class ContractCommissionAdmin(admin.ModelAdmin):
    list_display_links = None
    list_per_page = 10
    list_display = ['contract', 'commission_get', 'released_amount','commision_released']
    
    

    def has_add_permission(self, request):
        return False

    def released_contract_commission(modeladmin, request, queryset):

        # By -- pavan sharma - 28/05/2018
        try:
            queryset_result = queryset.filter(commision_released = False)
            payout_money = queryset_result.aggregate(Sum('commission_get'))
            payout_amount = float(payout_money['commission_get__sum'])*100
            transaction_id = stripe.Payout.create(
                amount= int(payout_amount),
                currency="gbp",
            )
            queryset_result.update(commision_released = True)
            return messages.add_message(request, messages.INFO, 'Status changed successfully.')
        except:
            return messages.add_message(request, messages.INFO, "Insufficient funds in Stripe account")
    def DownloadCommsissionCSV(modeladmin, request, queryset):
        response = HttpResponse(content_type='text/csv')
        filename = "commission.csv"
        response['Content-Disposition'] = u'attachment; filename="{0}"'.format(filename)
        ilewriter = csv.writer(response)
        ilewriter.writerow(["Id", "Provider Name", "Seeker Name", "Contract Name",
                            "Total Cost", "Release Amount", "Admin Commission", "Commission %"])
        for reg in queryset:
            ilewriter.writerow([reg.id, str(reg.contract.provider.first_name) + ' ' + str(reg.contract.provider.last_name), str(reg.contract.seeker.first_name),
                                reg.contract, float(reg.contract.total_cost), reg.released_amount, round(float(reg.commission_get)), round((reg.commission_get * 100) / reg.released_amount)])
        return response
    actions = ['released_contract_commission','DownloadCommsissionCSV']
    released_contract_commission.short_description = "Paid carer direct"
    released_contract_commission.allow_tags = True
    DownloadCommsissionCSV.short_description = "Download Commission CSV"
    DownloadCommsissionCSV.acts_on_all = True

    


admin.site.register(ContractCommission, ContractCommissionAdmin)


class NotificationAdmin(admin.ModelAdmin):

    list_per_page = 10
    list_display = ['content', 'notification_type', 'added']
    search_fields = ['content']
    list_display_links = None

    def get_queryset(self, request):
        Notification.objects.all().update(is_read = True)
        querySet = Notification.objects.all().order_by('-added')
        if request.user.is_superuser:
            return querySet
        return querySet
    
    def has_add_permission(self, request):
        return False
        
    
admin.site.register(Notification, NotificationAdmin)


class Admin_MessageAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['name', 'contact_number', 'message','added','updated']
    search_fields = ['name']

    def has_add_permission(self, request):
        return False


admin.site.register(Admin_Message, Admin_MessageAdmin)


class ContractCalendarAdmin(admin.ModelAdmin):
    list_display = ['event', 'event_start', 'event_end']
    #search_fields = ['contract_id']
    # list_filter = ['event']

    def has_add_permission(self, request):
        return False
    
    # def account_actions(self, obj):
    #     return format_html(
    #         '<a class="button" >Edit</a>&nbsp;'
    #         '<a class="button" >Cancel</a>&nbsp;',
    #         )


admin.site.register(ContractCalendar, ContractCalendarAdmin)


admin.site.register(UserCard)


class User_CareTypeAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['user', 'price']

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(User_CareType, User_CareTypeAdmin)
 

class AdminBlog(admin.ModelAdmin):
    list_per_page = 10
    list_display = ['name', 'added', 'updated', 'is_active']
    search_fields = ['name']


admin.site.register(Blog_Category,AdminBlog)


admin.site.register(ProviderPaymentDetails)



