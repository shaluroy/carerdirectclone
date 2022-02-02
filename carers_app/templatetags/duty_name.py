from django import template

register = template.Library()

@register.filter(name='duty_name')
def duty_name(value):
	list1 = []
	str1 = value.replace('[', '').strip('')
	str2 = str1.replace(']', '').strip('')
	str3 = str2.replace('u', '').strip('')
	list2 =  str(str3).strip('')
	return list2