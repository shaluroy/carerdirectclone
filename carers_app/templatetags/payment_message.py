from django import template
from carers_app.models import Contract
register = template.Library()

@register.filter(name='payment_message')
def payment_message(value):
	mssg = eval(value)[0]
	return mssg