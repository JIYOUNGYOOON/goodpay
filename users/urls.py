from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    path('agreement/', views.AgreementView.as_view(), name='agreement'),
    path('csregister/', views.CsRegisterView.as_view(), name='csregister'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('success/',views.success, name='success'),
    path('registerauth/', views.register_success, name='register_success'),
    path('activate/<str:uid64>/<str:token>/', views.activate, name='activate'),



  
]