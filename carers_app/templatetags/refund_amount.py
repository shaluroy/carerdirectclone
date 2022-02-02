
from django import template
from carers_app.models import Payment
register = template.Library()

@register.simple_tag
def get_refund_amount(value,total_value):
    refund_bool = False
    try:
        contract = Payment.objects.filter(contract__id=int(value)).order_by('-ask_refund')
        refund_value = contract[0].ask_refund
        if total_value - refund_value <=0:
            refund_bool = True
    except:
        refund_bool = False
   
    return refund_bool