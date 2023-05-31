from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.views.generic import ListView, DetailView, DeleteView, UpdateView, CreateView
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import Feed
from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str


# Create your views here.
def activate(request, uidb64, token):
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
            login(request, user)
            return redirect('home')
        else:
            messages.success(request, ("There was an error try again. Try entering the correct credentials"))
            return redirect('login')
    else:
        return render(request, 'core/Login.html')


def logout_user(request):
    logout(request)
    return redirect('login')

def forgot_password(request):
    email = request.POST.get('email')
    if request.method == 'POST':
        if User.objects.get(email=email).first():
            messages.success(request, ("A mail will be sent to your email"))
        else:
            messages.success(request, "Account doesn't exist")
            return redirect('signup')
    
    return render(request, 'core/forgot_password.html')


def change_password(request):
    password1 = request.POST.get('password1')
    password2 = request.POST.get('password2')
    if request.method == 'POST':
        if password1 == password2:
            pass
    
    return render(request, 'core/change_password.html')


class Home(ListView):
    template_name = 'core/feed_page.html'
    model = Feed
    context_object_name = 'homes'
    
    def get_queryset(self):
        return self.model.objects.all()
    