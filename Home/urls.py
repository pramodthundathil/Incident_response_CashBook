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
    path("LoginforApppasswordReset",views.LoginforApppasswordReset,name="LoginforApppasswordReset"),
    path("Resetloginpassword",views.Resetloginpassword,name="Resetloginpassword"),
    path("AddExpence",views.AddExpence,name="AddExpence"),
    path("FinaceAdvice",views.FinaceAdvice,name="FinaceAdvice"),
    path("AdminIndex",views.AdminIndex,name="AdminIndex"),
    path("deleteadvice/<int:pk>",views.deleteadvice, name="deleteadvice"),
    path("AdvisorIndex",views.AdvisorIndex,name="AdvisorIndex"),
    path("Advisoranswer/<int:pk>",views.Advisoranswer, name="Advisoranswer"),
    path("AdvisorIndex",views.AdvisorIndex,name="AdvisorIndex"),
    path("News",views.News,name="News"),
    path("Reports",views.Reports,name="Reports"),
    path("Profile",views.Profile,name="Profile"),
]