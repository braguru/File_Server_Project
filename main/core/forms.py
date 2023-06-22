from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm


class SetPasswordForm(SetPasswordForm):
    class Meta:
        model = get_user_model()
        fields = ['newpassword1', 'newpassword2']
        
        def __init__(self, *args, **kwargs):
            super(SetPasswordForm, self).__init__(*args, **kwargs)
            
            self.fields['newpassword1'].widget.attrs['class'] = "form-control p-2 mb-5"
            self.fields['newpassword2'].widget.attrs['class'] = "form-control p-2 mb-5"