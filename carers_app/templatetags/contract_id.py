from django import template
from carers_app.models import Contract
register = template.Library()

@register.filter(name='contract_id')
def contract_id(value):
	contract_id = eval(value)[-1]
	contract = Contract.objects.get(id=int(contract_id))
	return contract.id