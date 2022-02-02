from django import forms
from django.forms import ModelForm, Textarea
from carers_app.models import User, Admin_Message 


class ProfileForm(ModelForm):
		class Meta:
			model=User
			fields = ['first_name','last_name','contact_number','email','telephone_number']

		def __init__(self, *args, **kwargs):
			super(ProfileForm, self).__init__(*args, **kwargs)

			self.fields['first_name'].widget.attrs = {'class': 'formControl2', 'placeholder': 'First Name','disabled':True , 'maxlength': 30}
			self.fields['last_name'].widget.attrs = {'class': 'formControl2', 'placeholder': 'Last Name','disabled':True, 'maxlength': 30}
			self.fields['contact_number'].widget.attrs = {'class': 'formControl2', 'placeholder': 'Contact Number','disabled':True}
			self.fields['email'].widget.attrs = {'class': 'formControl2', 'placeholder': 'Email Address','disabled':True,'maxlength':150}
			self.fields['telephone_number'].widget.attrs = {'class': 'formControl2', 'placeholder': 'Mobile Number','disabled':True,'required':"false"}
			for key, field in self.fields.iteritems():
					self.fields['telephone_number'].required = False
					self.fields['contact_number'].required = False
			

class ContactForm(ModelForm):
		class Meta:
			model=Admin_Message
			fields = ['name','email','contact_number', 'message']
			widgets = {
		          'message': Textarea(attrs={'class': 'formControl2 heightControl', 'placeholder': 'Message (Max 255 characters are allowed)', 'rows':5, 'maxlength':"255"}),
		        }

		def __init__(self, *args, **kwargs):
			super(ContactForm, self).__init__(*args, **kwargs)
			self.fields['name'].widget.attrs = {'class': 'formControl2', 'placeholder': 'Name'}
			self.fields['email'].widget.attrs = {'class': 'formControl2', 'placeholder': 'Email Address'}
			self.fields['contact_number'].widget.attrs = {'class': 'formControl2', 'placeholder': 'Contact Number'}
			#self.fields['message'].widget.attrs = {'class': 'formControl2 heightControl', 'placeholder': 'Message', 'rows':4}
									