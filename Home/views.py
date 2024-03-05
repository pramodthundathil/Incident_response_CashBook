from django.shortcuts import render, redirect , HttpResponse
from .forms import UserAddForm
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout

from django.conf import settings
from django.core.mail import send_mail,EmailMessage
from django.template.loader import render_to_string

from django.contrib.auth.decorators import login_required
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .tokens import account_activation_token

from .models import CustomeUserModel, IncidentLogs, CustomUser, ApppasswordAttempt
from django.contrib.auth.decorators import login_required

from .decorators import AppPasswordChecker


@login_required(login_url="SignIn")
def Index(request):
    return render(request,'index.html')


def SignIn(request):
    client_ip = request.META.get('HTTP_X_FORWARDED_FOR', None)
    if not client_ip:
        client_ip = request.META.get('REMOTE_ADDR', None)

    print(client_ip,"............................................................")
    if request.method == "POST":
        uname = request.POST['uname']
        pswd = request.POST['pswd']

        user = authenticate(request,username = uname, password = pswd)
        if user is not None:
            login(request,user)
            try:
                Modelcount = CustomeUserModel.objects.get(user = user)
                Modelcount.login_attempt = 0
                Modelcount.save()
            except:
                pass
            return redirect("Index")
        else:
            try:
                user = User.objects.get(username = uname)
                email = user.email
                Modelcount = CustomeUserModel.objects.get(user = user)
                Modelcount.login_attempt += 1
                Modelcount.save()

                if Modelcount.login_attempt >= 3:
                    user.is_active = False
                    user.save()
                    current_site = get_current_site(request)
                    mail_subject = 'Re-Activate your  account.'
                    message = render_to_string('emailbody2.html', {'user': user,
                                                                            'domain': current_site.domain,
                                                                            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                                                                            'token':account_activation_token.make_token(user),})
                    
                    email = EmailMessage(mail_subject, message, to=[email])
                    email.send(fail_silently=True)
                    messages.info(request,"Your Account Was Blocked Please Check Your Email To Reactivate instractions")
                    IncidentLogs.objects.create(user = user, incident = f"Account Was blocked due to {Modelcount.login_attempt} failed login attempt",ipaddress = client_ip )

                    return redirect('SignIn')

                else:
                    IncidentLogs.objects.create(user = user, incident = f"Account have {Modelcount.login_attempt} unsuccessfull login attempt",ipaddress = client_ip )

                    mail_subject = 'Invalid password attempt your account.'
                    message = render_to_string('emailbody3.html', {'user': user,"attempt":3-Modelcount.login_attempt})
                    
                    email = EmailMessage(mail_subject, message, to=[email])
                    email.send()
                    
                    messages.info(request,f"You entered wrong Password you have {3-Modelcount.login_attempt} attempt left")
                    return redirect('SignIn')
                
            except:
                try:
                    user = User.objects.get(username = uname)
                    if CustomeUserModel.objects.filter(user = user).exists():
                        pass 
                    else:
                        Modelcount = CustomeUserModel.objects.create(user = user,login_attempt = 1 )

                    IncidentLogs.objects.create(user = user, incident = f"Account have {Modelcount.login_attempt} unsuccessfull login attempt",ipaddress = client_ip )
                    messages.info(request,f"You entered wrong Password you have {3-Modelcount.login_attempt} attempt left")
                    return redirect('SignIn')
                except:
                    messages.info(request,"Invalid Credentials....")
                    return redirect('SignIn')
        
    return render(request,"login.html")

def SignUp(request):
    form = UserAddForm()
    if request.method == "POST":
        form = UserAddForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            email = user.email 

        
            current_site = get_current_site(request)
            mail_subject = 'Activate your E-Cart account.'
            message = render_to_string('emailbody.html', {'user': user,
                                                                     'domain': current_site.domain,
                                                                     'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                                                                     'token':account_activation_token.make_token(user),})

            email = EmailMessage(mail_subject, message, to=[email])
            email.send(fail_silently=True)
            messages.info(request,"User created....")

            return redirect("SignIn")


    context = {
        "form":form
    }
    return render(request,"register.html",context)


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        # return redirect('home')
        messages.info(request,'Thank you for your email confirmation. Now you can login your account.')
        return redirect("SignIn")
    else:
        return HttpResponse('Activation link is invalid!')
    
def SignOut(request):
    logout(request)
    return redirect('SignIn')

# Income Transactions income and expense

@login_required(login_url="SignIn")
def AddIncome(request):
    return render(request,"income.html")


@AppPasswordChecker
@login_required(login_url="SignIn")
def enterpassword(request):
    client_ip = request.META.get('HTTP_X_FORWARDED_FOR', None)
    if not client_ip:
        client_ip = request.META.get('REMOTE_ADDR', None)
    if request.method == "POST":
        pswd1 = request.POST['pswd1']
        user = CustomUser.objects.get(user = request.user)
        email = request.user.email

        if user.check_encrypted_password(pswd1):
            try:
                att = ApppasswordAttempt.objects.get(custome = user)
                
            except:
                pass
            print("Correct")
            if user.active == True:
                att.passwordattempt = 0
                att.save()
                return redirect("AddIncome")
            else:
                IncidentLogs.objects.create(user = user.user, incident = "Your App Password is blocked app password attempt",ipaddress = client_ip )

                messages.info(request,"Your App Password is blocked please activate it from your email")
                return redirect("enterpassword")
        else: 
            # try:
                att = ApppasswordAttempt.objects.get(custome = user)
                att.passwordattempt += 1
                att.save()
            
                if att.passwordattempt >= 3:
                    user.active = False
                    user.save()
                    IncidentLogs.objects.create(user = user.user, incident = f"Account have {att.passwordattempt} unsuccessfull app password  attempt blocked your app password",ipaddress = client_ip )
                    mail_subject = 'Invalid password attempt your account.'
                    message = render_to_string('emailbody4.html', {'user': user.user,"attempt":3-att.passwordattempt})
                    
                    email = EmailMessage(mail_subject, message, to=[email])
                    email.send()

                    messages.info(request,f"Password Enterd incorrect..{att.passwordattempt} attempt. App password is blocked Please Check email")
                    return redirect("enterpassword")
            # except:
                if ApppasswordAttempt.objects.filter().exists():
                    att = ApppasswordAttempt.objects.get(custome = user)
                    # att.passwordattempt += 1
                    # att.save()
                    IncidentLogs.objects.create(user = user.user, incident = f"Account have {att.passwordattempt} unsuccessfull app password  attempt ",ipaddress = client_ip )

                    mail_subject = 'Invalid password attempt your account.'
                    message = render_to_string('emailbody4.html', {'user': user.user,"attempt":3-att.passwordattempt})
                    
                    email = EmailMessage(mail_subject, message, to=[email])
                    email.send()
                    messages.info(request,f"Password Enterd incorrect..{3- att.passwordattempt} attempt left")
                    return redirect("enterpassword")
                else:
                    appass = ApppasswordAttempt.objects.create(custome = user,passwordattempt = 1)
                    appass.save()
                    mail_subject = 'Invalid password attempt your account.'
                    message = render_to_string('emailbody4.html', {'user': user.user,"attempt":3-appass.passwordattempt})
                    
                    email = EmailMessage(mail_subject, message, to=[email])
                    email.send()
                    IncidentLogs.objects.create(user = user.user, incident = f"Account have {appass.passwordattempt} unsuccessfull app password  attempt ",ipaddress = client_ip )

                    messages.info(request,f"Password Enterd incorrect..{3- appass.passwordattempt} attempt left")
                    return redirect("enterpassword")


            # print("incorrect")

    return render(request, "passwordenter.html")

@login_required(login_url="SignIn")
def Createapppassword(request):
    if request.method == "POST":
        pswd1 = request.POST['pswd1']
        pswd2 = request.POST['pswd2']

        if pswd1 == pswd2:
            user = CustomUser.objects.create(user = request.user , encrypted_password = pswd1)
            user.set_password(pswd1)
            user.save()
            return redirect("Index")
        
    return render(request,"apppasswordcreate.html")


def IncidentLog(request):
    incident = IncidentLogs.objects.filter(user = request.user)
    context = {
        "incident":incident
    }
    return render(request,"incidentlog.html",context)

