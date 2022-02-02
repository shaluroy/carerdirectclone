from django import template
from carers_app.models import Contract
register = template.Library()

@register.filter(name='contract_cost')
def contract_cost(value):
	contract_id = eval(value)[-1]
	contract = Contract.objects.get(id=int(contract_id))
	return contract.total_cost