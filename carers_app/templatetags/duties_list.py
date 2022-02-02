from django import template

register = template.Library()

@register.filter(name='duties_list')
def duties_list(value):
	list1 = []
	str1 = value.replace('[', '').strip('')
	str2 = str1.replace(']', '').strip('')
	str3 = str2.replace('u', '').strip('')
	list2 =  str(str3).strip('').split(',')
	return list2

