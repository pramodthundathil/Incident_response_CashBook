from django.shortcuts import render, redirect , HttpResponse
from .forms import UserAddForm, IncomeForm, ExpenceForm
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout

from .decorators import admin_only
from django.conf import settings
from django.core.mail import send_mail,EmailMessage
from django.template.loader import render_to_string

from django.contrib.auth.decorators import login_required
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .tokens import account_activation_token

from .models import CustomeUserModel, IncidentLogs, CustomUser, ApppasswordAttempt, Income, Expense, Advice
from django.contrib.auth.decorators import login_required

from .decorators import AppPasswordChecker

from django.db.models import Sum, Q
from datetime import datetime , timedelta
from django.utils.timezone import localtime, timedelta
current_month = localtime().month
current_year = localtime().year

# Calculate the start date for the current month
start_of_current_month = localtime().replace(day=1, hour=0, minute=0, second=0, microsecond=0)

# Calculate the start date for 30 days before the current date
thirty_days_ago = localtime() - timedelta(days=30)


@admin_only
@login_required(login_url="SignIn")
def Index(request):

    income_data = Income.objects.filter(Q(user_id=request.user) &
    (
        (Q(date__month=current_month, date__year=current_year) & Q(date__gte=start_of_current_month)) |
        (Q(date__gte=thirty_days_ago) & Q(date__lt=start_of_current_month))
    )
    ).aggregate(total_amount=Sum('amount'))['total_amount'] or 0

    expence_data = Expense.objects.filter(Q(user_id=request.user) &
    (
        (Q(date__month=current_month, date__year=current_year) & Q(date__gte=start_of_current_month)) |
        (Q(date__gte=thirty_days_ago) & Q(date__lt=start_of_current_month))
    )
    ).aggregate(total_amount=Sum('amount'))['total_amount'] or 0

    context = {
        "income_data":income_data,
        "expence_data":expence_data
    }
    return render(request,'index.html',context)


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
            mail_subject = 'Activate your account.'
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
    form1 = ExpenceForm()
    form = IncomeForm()
    income = Income.objects.filter(user=request.user)
    expence = Expense.objects.filter(user = request.user)
    if request.method == "POST":
        form = IncomeForm(request.POST)
        if form.is_valid():
            val = form.save()
            val.user = request.user
            val.save()
            messages.info(request,"Income Data Added")
            return redirect("AddIncome")
        else:
            messages.info(request,"Something Wrong..")
            return redirect("AddIncome")

    context = {
        "form1":form1,
        "form":form,
        "income":income,
        "expence":expence
    }
    return render(request,"income.html",context)

@login_required(login_url="SignIn")
def AddExpence(request):
    if request.method == "POST":
        form = ExpenceForm(request.POST)
        if form.is_valid():
            val = form.save()
            val.user = request.user
            val.save()
            messages.info(request,"Expence Data Added")
            return redirect("AddIncome")
        else:
            messages.info(request,"Something Wrong..")
            return redirect("AddIncome")

@AppPasswordChecker
@login_required(login_url="SignIn")
def enterpassword(request):
    client_ip = request.META.get('HTTP_X_FORWARDED_FOR', None)
    if not client_ip:
        client_ip = request.META.get('REMOTE_ADDR', None)
    current_site = get_current_site(request)
    if request.method == "POST":
        pswd1 = request.POST['pswd1']
        user1 = CustomUser.objects.get(user = request.user)
        email = request.user.email

        print(user1)

        if user1.check_encrypted_password(pswd1):
            try:
                att = ApppasswordAttempt.objects.get(custome = user1)
            # att = att[0] 
            except:
                att = ApppasswordAttempt.objects.create(custome = user1,passwordattempt = 0)
                att.save()
            # print("Correct")
            if user1.active == True:
                att.passwordattempt = 0
                att.save()
                return redirect("AddIncome")
            else:
                IncidentLogs.objects.create(user = user1.user, incident = "Your App Password is blocked app password attempt",ipaddress = client_ip )
                mail_subject = 'Invalid password attempt your account. Password Blocked'
                message = render_to_string('emailbody4.html', {'user': user1.user,"attempt":3-att.passwordattempt,'domain': current_site})
                    
                email = EmailMessage(mail_subject, message, to=[email])
                email.send()
                messages.info(request,"Your App Password is blocked please activate it from your email")
                return redirect("enterpassword")
        else: 
            # try:
                att = ApppasswordAttempt.objects.get(custome = user1)
                att.passwordattempt += 1
                att.save()
            
                if att.passwordattempt >= 3:
                    user1.active = False
                    user1.save()
                    current_site = get_current_site(request)

                    IncidentLogs.objects.create(user = user1.user, incident = f"Account have {att.passwordattempt} unsuccessfull app password  attempt blocked your app password",ipaddress = client_ip )
                    mail_subject = 'Invalid password attempt your account. Password Blocked'
                    message = render_to_string('emailbody4.html', {'user': user1.user,"attempt":3-att.passwordattempt,'domain': current_site})
                    
                    email = EmailMessage(mail_subject, message, to=[email])
                    email.send()

                    messages.info(request,f"Password Enterd incorrect..{att.passwordattempt} attempt. App password is blocked Please Check email")
                    return redirect("enterpassword")
            # except:
                if ApppasswordAttempt.objects.filter().exists():
                    att = ApppasswordAttempt.objects.get(custome = user1)
                    # att.passwordattempt += 1
                    # att.save()
                    IncidentLogs.objects.create(user = user1.user, incident = f"Account have {att.passwordattempt} unsuccessfull app password  attempt ",ipaddress = client_ip )

                    mail_subject = 'Invalid password attempt your account.'
                    message = render_to_string('emailbody4.html', {'user': user1.user,"attempt":3-att.passwordattempt})
                    
                    email = EmailMessage(mail_subject, message, to=[email])
                    email.send()
                    messages.info(request,f"Password Enterd incorrect..{3- att.passwordattempt} attempt left")
                    return redirect("enterpassword")
                else:
                    appass = ApppasswordAttempt.objects.create(custome = user1,passwordattempt = 1)
                    appass.save()
                    mail_subject = 'Invalid password attempt your account.'
                    message = render_to_string('emailbody4.html', {'user': user1.user,"attempt":3-appass.passwordattempt})
                    
                    email = EmailMessage(mail_subject, message, to=[email])
                    email.send()
                    IncidentLogs.objects.create(user = user1.user, incident = f"Account have {appass.passwordattempt} unsuccessfull app password  attempt ",ipaddress = client_ip )

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


@login_required(login_url="SignIn")
def IncidentLog(request):
    incident = IncidentLogs.objects.filter(user = request.user)
    context = {
        "incident":incident
    }
    return render(request,"incidentlog.html",context)


def LoginforApppasswordReset(request):
    if request.method == "POST":
        uname = request.POST['uname']
        pswd = request.POST['pswd']
        user = authenticate(request,username = uname, password = pswd)
        if user is not None:
            login(request,user)
            return redirect("Resetloginpassword")
        else:
            messages.info(request,"Incorrect password attempt")
            return redirect('LoginforApppasswordReset')
    return render(request,"loginforApppasswordreset.html")


@login_required(login_url="SignIn")
def Resetloginpassword(request):
    if request.method == "POST":
        pswd1 = request.POST['pswd1']
        pswd2 = request.POST['pswd2']

        if pswd1 == pswd2:
            user = CustomUser.objects.get(user = request.user)
            user.set_password(pswd1)
            user.active = True
            user.save()
            appatt = ApppasswordAttempt.objects.get(custome = user)
            appatt.passwordattempt = 0
            appatt.save()
            logout(request)
            messages.info(request,"App Password Reset Completed......")
            return redirect("SignIn")
        else:
            messages.info(request,"Password Do not Match")
            return redirect("Resetloginpassword")

    return render(request,'resetloginpassword.html')


@login_required(login_url="SignIn")
def FinaceAdvice(request):
    myadvices = Advice.objects.filter(user = request.user)
    if request.method == "POST":
        ques = request.POST['ques']
        advice = Advice.objects.create(question = ques, user = request.user)
        advice.save()
        messages.info(request,"Advice Asked")
        return redirect("FinaceAdvice")

    context = {
        "myadvice":myadvices
    }
    return render(request,"financialadvices.html",context)

def deleteadvice(request,pk):
    Advice.objects.get(id = pk).delete()
    messages.info(request,"Advice deleted")
    return redirect("FinaceAdvice")

from django.contrib.auth.models import Group

def AdminIndex(request):
    form = UserAddForm()
    users = User.objects.filter(groups__name = "advisor")
    if request.method == "POST":
        form = UserAddForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.save()
            group = Group.objects.get(name='advisor')
            user.groups.add(group) 
            user.save()
            messages.info(request,"Advisor addedd")
            return redirect("AdminIndex")

    context = {
        "form":form,
        "users":users
    }
    return render(request,"adminindex.html",context)


def AdvisorIndex(request):
    advise = Advice.objects.all()

    context = {
        "advise":advise
    }
    return render(request,'advisorindex.html',context)

def Advisoranswer(request,pk):
    adv = Advice.objects.get(id = pk)
    if request.method == "POST":
        ad = request.POST['advise']
        adv.advice  = ad
        adv.save()
        messages.info(request,"data addedd")
        return redirect("AdvisorIndex")
    return redirect("AdvisorIndex")
        

def News(request):
    import requests
    url = "https://newsapi.org/v2/everything?q=tesla&from=2024-02-19&sortBy=publishedAt&apiKey=fb0fea13be284ffa8c4e03b6a50d3985"
    res = requests.get(url = url)
    data = res.json()
    news = data["articles"]

    context = {
        "news":news
    }
    return render(request,"news.html",context)


