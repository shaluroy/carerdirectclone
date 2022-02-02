# -*- coding:  utf-8 -*-
from django import template
from carers_app.models import *

register = template.Library()

@register.filter(name='hourly_rate')
def hourly_rate(value):
	user = User.objects.get(pk=value)
	price = User_CareType.objects.filter(user=user)
	Hourly= 0
	over= 0
	livein= 0
	mylist = []
	for i in price:
		if int(i.caretype.id) == 1:
			mylist.append(str(i.caretype.name).title()+': £'+str(i.price))
		elif int(i.caretype.id) == 2:
			mylist.append(str(i.caretype.name).title()+': £'+str(i.price))
		elif int(i.caretype.id) == 3:
			mylist.append(str(i.caretype.name).title()+': £'+str(i.price))
	return mylist[::-1]




	