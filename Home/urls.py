from django.urls import path
from .import views


urlpatterns = [

    path("",views.SignIn,name="SignIn"),
    path("SignUp",views.SignUp,name="SignUp"),
    path("SignOut",views.SignOut,name="SignOut"),
    path('activate/<slug:uidb64>/<slug:token>/',views.activate, name='activate'),
    path("Index",views.Index,name="Index"),
    path("AddIncome",views.AddIncome,name="AddIncome"),
    path("enterpassword",views.enterpassword,name="enterpassword"),
    path("Createapppassword",views.Createapppassword,name="Createapppassword"),
    path("IncidentLog",views.IncidentLog,name="IncidentLog"),

    

]