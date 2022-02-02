from django import template
from carers_app.models import * 
from datetime import datetime, timedelta

register = template.Library()

@register.filter(name='contract_days')
def contract_days(value):
	contract = Contract.objects.get(pk=value)
	end_date = contract.end_date+timedelta(days=1)
	return str(end_date - contract.start_date).split(',')[0] 
	

