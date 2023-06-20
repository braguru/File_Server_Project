from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.views.generic import ListView, DetailView, DeleteView, UpdateView, CreateView
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from .forms import SetPasswordForm
from django.db.models.query_utils import Q
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import File
from django.conf import settings
from main.thread import EmailThread

# Create your views here.
def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None
        
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        
        messages.success(request, "Email Confirmation success, You can login now")
        return redirect('login')
    else:
        messages.error(request, "Activation link is invalid or expired")
        
    return redirect('home')


def ActivateEmail(request, user, to_email):
    mail_subject = 'Activate your user account'
    message = render_to_string('core/activate.html', {
                               'user': user.username,
                               'domain': get_current_site(request).domain,
                               'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                               'token': account_activation_token.make_token(user),
                               'protocol': 'https' if request.is_secure() else 'http'
    }
    )
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        messages.success(request, f'Dear {user} check your email {to_email} inbox to activate and complete your registration')
    else:
        messages.error(request, f"Check if you typed your email correctly.")



def SignUp_user(request):
    if request.method == 'POST':
        username = request.POST.get('uname')
        firstname = request.POST.get('fname')
        lastname = request.POST.get('lname')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        
        if User.objects.filter(email=email).first():
            messages.success(request, "Email already exist")
            return redirect('signup')
        elif User.objects.filter(username=username).first():
            messages.success(request, ("Username already exist"))
        elif password1 == password2:
            user = User.objects.create_user(username, email, password1)
            user.first_name = firstname
            user.last_name = lastname
            user.is_active = False
            user.save()
            ActivateEmail(request, user, email)
            messages.success(request, ("Account created successfully"))
           
            return redirect('login')
        else:
            messages.success(request, ("Passwords don't match. Try Again"))

    return render(request, "core/SignUp.html")

def login_user(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=User.objects.get(email=email), password=password)
        
        if user is not None:
            if user.is_staff:
                login( request, user)
                return redirect('admin/')
            else:
                login(request, user)
                return redirect('home')
        else:
            messages.success(request, ("There was an error try again. Try entering the correct credentials"))
            return redirect('login')
    else:
        return render(request, 'core/Login.html')


@login_required
def logout_user(request):
    logout(request)
    return redirect('login')


def forgot_password(request):
    if request.method == 'POST':
        user_email = request.POST.get('email')
        associated_user = get_user_model().objects.filter(Q(email=user_email)).first()
        if associated_user:
            subject = 'Reset your password'
            message = render_to_string('core/reset_password.html', {
                               'user': associated_user,
                               'domain': get_current_site(request).domain,
                               'uid': urlsafe_base64_encode(force_bytes(associated_user.pk)),
                               'token': account_activation_token.make_token(associated_user),
                               'protocol': 'https' if request.is_secure() else 'http'
            }
            )
            email = EmailMessage(subject, message, to=[associated_user.email])
            if email.send():
                messages.success(request, ("A mail will be sent to your email"))
                return redirect('login')
        else:
            messages.success(request, "Account doesn't exist")
            return redirect('signup')
    
    return render(request, 'core/forgot_password.html')


def reset_password(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None
        
    if user is not None and account_activation_token.check_token(user, token):
        if request.method == 'POST':
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')
            if password1 == password2:
                user.save()
                messages.success(request, "Password successfully changed. You can login now")
                return redirect('login')
            else:
                messages.error(request, "Passwords do not match")
    else:
        messages.error(request, "Link is expired")
        
    return render(request, 'core/change_password.html')


# def change_password(request):
#     user = request.user
#     # password1 = request.POST.get('password1')
#     # password2 = request.POST.get('password2')
#     if request.method == 'POST':
#         form = SetPasswordForm(user, request.POST)
#         if form.is_valid():
#             form.save()
#             messages.success(request, "Password successfully changed")
#             return redirect('login')
#         else:
#             for error in list(form.erros.value()):
#                 messages.error(request, error)
#         # if password1 == password2:
#         #     user.save()
#         #     messages.success(request, "Password successfully changed")
#         #     return redirect('login')
#         # else:
#         #     # for error in list(form.erros.value()):
#         #     messages.error(request, "Passwords do not match")
#     form = SetPasswordForm(user)
#     return render(request, 'core/change_password.html', {'form': form})


class Home(LoginRequiredMixin, ListView):
    template_name = 'core/feed_page.html'
    model = File
    context_object_name = 'files'
    
    
    def get_queryset(self, **kwargs):
        query = self.request.GET.get('q')
        if query:
            feed = self.model.objects.filter(
                Q(filename__icontains=query) |
                Q(description__icontains=query) 
            )
        else:
            return self.model.objects.all()
        return feed
    
    
    

def admin_page(request):
    return render(request, 'core/Admin_Page.html')

    
class Feed_Detail(LoginRequiredMixin, DetailView):
    template_name = 'core/feed_page_detail.html'
    model = File
    context_object_name = 'file'
    
    
@login_required
def send_file_page(request, id):
    obj = get_object_or_404(File, pk=id)
    file1 = obj.pdf
    file2 = obj.audio
    file3 = obj.video
    file4 = obj.image
    
    if request.method == 'POST':
        user_email = request.POST.get('email')
        
        if user_email:
            subject = obj.filename
            to = user_email
            message = obj.description
            email = EmailMessage(subject, message, settings.EMAIL_HOST_USER, [to])
            if obj.pdf:
                email.attach_file(file1.path)
            elif obj.audio:
                email.attach_file(file2.path)
            elif obj.image:
                email.attach_file(file4.path)
            elif obj.video:
                email.attach_file(file3.path)
            else:
                return "No file selected"
            EmailThread(email).start()
            
            
            if email.send():
                messages.success(request, ("File sent"))
                return redirect('home')
    
    return render(request, 'core/file_email.html', {'obj':obj})
    