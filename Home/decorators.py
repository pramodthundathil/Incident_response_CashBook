from django.shortcuts import redirect 
from .models import CustomUser



def AppPasswordChecker(view_func):
    def wapperfunc(request,*args,**kwargs):
        user = request.user
        if CustomUser.objects.filter(user = user).exists():
            return view_func(request,*args, **kwargs)
        else:
            return redirect("Createapppassword")
    return wapperfunc

    