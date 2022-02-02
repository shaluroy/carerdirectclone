from django import template
#from carers_app.models import *
from chat.models import * 
from datetime import datetime, timedelta

register = template.Library()

@register.filter(name='unread_count')
def unread_count(value):
	room = Room.objects.get(pk=value)
	userchat = UserChat.objects.filter(sender=room.user2, receiver=room.user1, is_read=False) 
	return int(userchat.count())