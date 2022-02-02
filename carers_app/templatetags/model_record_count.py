from django import template
from django.contrib.auth.models import *
from carers_app.models import *

register = template.Library()

@register.filter(name='count')
def count(model):
	print dir(model.show_full_result_count)




























	#record_count = model.objects.count()
	#return str(model['name']).objects.all().count()