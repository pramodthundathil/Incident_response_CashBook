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

#decorators for user wise redirect pages...............
def admin_only(view_func):
    def wrapper_function(request, *args, **kwargs):
        group = None
        if request.user.groups.exists():
            group = request.user.groups.all()[0].name
            
        if group == None:
            return view_func(request, *args, **kwargs)
       
        if group == 'admin':
            return redirect('AdminIndex')
        
        if group == 'advisor':
            return redirect('AdvisorIndex')
              
    return wrapper_function



    