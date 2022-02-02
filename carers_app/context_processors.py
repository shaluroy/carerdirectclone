from carers_app.models import User, Contract, Invoice, Notification, UserDocument
from django.contrib.auth.models import Group
from datetime import datetime, timedelta
from django.db.models import Q
import pytz
from django.utils import timezone


def users_count(request):
	count = datetime.now().weekday()
	day = datetime.now().date().day
	last_week_start_date = datetime.now().date()-timedelta(days=(7+count))
	last_week_end_date = datetime.now().date()-timedelta(days=(count+1))
	last_month_start_date = datetime.now().date()-timedelta(days=(30+day))
	last_month_end_date = datetime.now().date()-timedelta(days=(day))
	users = User.objects.all()
	contracts = Contract.objects.all()
	invoice = Invoice.objects.all().count()
	notification = Notification.objects.filter(Q(notification_type="Payment")|Q(notification_type="admincontract"), is_read=False)
	# completed_contracts = contracts.filter(status="complete").count()
	seeker_count = users.filter(Q(groups__name="SS")|Q(groups__name="Service Seeker")).count()
	provider_count = users.filter(Q(groups__name="SP")|Q(groups__name="Service Provider")).count()
	lastweek_complete_contracts = contracts.filter(status="Completed", end_date__range=(last_week_start_date, last_week_end_date)).count()
	lastweek_SS_count = users.filter(Q(groups__name="SS")|Q(groups__name="Service Seeker"), date_joined__date__range=(last_week_start_date, last_week_end_date)).count()
	lastweek_SP_count = users.filter(Q(groups__name="SP")|Q(groups__name="Service Provider"), date_joined__date__range=(last_week_start_date, last_week_end_date)).count()
	lastmonth_complete_contracts = contracts.filter(status="Completed", end_date__range=(last_month_start_date, last_month_end_date)).count()
	lastmonth_SS_count = users.filter(Q(groups__name="SS")|Q(groups__name="Service Seeker"), date_joined__date__range=(last_month_start_date, last_month_end_date)).count()
	lastmonth_SP_count = users.filter(Q(groups__name="SS")|Q(groups__name="Service Provider"), date_joined__date__range=(last_month_start_date, last_month_end_date)).count()
	
	return {'users_count': users.count(),
			'seeker_count': seeker_count,
			'provider_count': provider_count,
			'lastweek_SS':lastweek_SS_count,
			'lastweek_SP':lastweek_SP_count,
			'lastmonth_SS':lastmonth_SS_count,
			'lastmonth_SP':lastmonth_SP_count,
			'contract_count':contracts.count(),
			'invoice_count': invoice,
			'lastweek_complete_contracts':lastweek_complete_contracts,
			'lastmonth_complete_contracts':lastmonth_complete_contracts,
			'notification': notification,
			'count': notification.count()						
			}

			

def users_doc_date_check(request):
	if request.user.is_anonymous or request.user.is_superuser or request.user.is_staff:
		return {'check': 'True'}
	else:
		group = Group.objects.get(user = request.user.id).name
		if group=="Service Provider":
			today = datetime.today().date()
			#here is check
			user_doc = UserDocument.objects.filter(user=request.user)
			if user_doc.count()>0:
				insurance_expire_date = user_doc[0].insurance_expire_date
				dbs_expire_date = user_doc[0].dbs_expire_date
				insurance_expire_alert = False
				dbs_expire_alert = False
				dbs_expired = False
				insurance_expired = False
				dbs_expire_days_left = 0
				insurance_expire_days_left = 0
				if dbs_expire_date != None:
					if dbs_expire_date==today:
						dbs_expire_days_left = 0
					else:
						dbs_expire_days_left = str(dbs_expire_date-today).split(' ')[0]
					
					if (int(dbs_expire_days_left)<=30 and int(dbs_expire_days_left)>-1) or (dbs_expire_date==today):
						dbs_expire_alert = True

					if int(dbs_expire_days_left)<0:
						request.user.publish=False
						request.user.save()
						dbs_expire_alert = True
						dbs_expired = True
				
				if insurance_expire_date != None:
					if insurance_expire_date==today:
						insurance_expire_days_left = 0
					else:
						insurance_expire_days_left =  str(insurance_expire_date-today).split(' ')[0]
				
					if (int(insurance_expire_days_left)<=30 and int(insurance_expire_days_left)>-1) or (insurance_expire_date==today):
						insurance_expire_alert = True
					
					if int(insurance_expire_days_left)<0:
						request.user.publish=False
						request.user.save()
						insurance_expire_alert = True
						insurance_expired = True

				return {'dbs_expire_alert':dbs_expire_alert,
						'insurance_expire_alert':insurance_expire_alert,
						'dbs_expire_days_left':dbs_expire_days_left,
						'insurance_expire_days_left':insurance_expire_days_left,
						'dbs_expired':dbs_expired,
						'insurance_expired':insurance_expired
						}
	return {'check': 'True'}
