# users/views.py

from xml.dom import ValidationErr
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from .decorators import *
from .models import User
from django.views.generic import View
from django.contrib import messages

from django.core.exceptions import PermissionDenied
from .forms import CsRegisterForm, RegisterForm
from django.views.generic import CreateView

from django.urls import reverse
from .helper import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator


@method_decorator(logout_message_required, name='dispatch')
class AgreementView(View):
    def get(self, request, *args, **kwargs):
     request.session['agreement'] = False
     return render(request, 'users/agreement.html')

    def post(self, request, *args, **kwarg):
        if request.POST.get('agreement1', False) and request.POST.get('agreement2', False):
            request.session['agreement'] = True

            if request.POST.get('csregister') == 'csregister':       
                return redirect('/users/csregister/')
            else:
                return redirect('/users/register/')
        else:
            messages.info(request, "약관에 모두 동의해주세요.")
            return render(request, 'users/agreement.html')

class CsRegisterView(CreateView):
    model = User
    template_name = 'users/register_cs.html'
    form_class = CsRegisterForm

    def get(self, request, *args, **kwargs):
        if not request.session.get('agreement', False):
            raise PermissionDenied
        request.session['agreement'] = False
        return super().get(request, *args, **kwargs)
        
    def get_success_url(self):
        self.request.session['register_auth'] = True
        return reverse('users:success')

    def form_valid(self, form):
        self.object = form.save()
        return redirect(self.get_success_url())

    def form_valid(self, form):
        self.object = form.save()

        send_mail(
        '{}님의 회원가입 인증메일 입니다.'.format(self.object.user_id),
        [self.object.email],
        html=render_to_string('users/register_email.html', {
            'user': self.object,
            'uid': urlsafe_base64_encode(force_bytes(self.object.pk)).encode().decode(),
            'domain': self.request.META['HTTP_HOST'],
            'token': default_token_generator.make_token(self.object),
        }),
        )
        return redirect(self.get_success_url())

def activate(request, uid64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uid64))
        current_user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationErr):
        messages.error(request, '메일 인증에 실패했습니다.')
        return redirect('users:login')

    if default_token_generator.check_token(current_user, token):
        current_user.is_active = True
        current_user.save()

        messages.info(request, '메일 인증이 완료 되었습니다. 회원가입을 축하드립니다!')
        return redirect('users:login')

    messages.error(request, '메일 인증에 실패했습니다.')
    return redirect('users:login')

def register_success(request):
        if not request.session.get('register_auth', False):
            raise PermissionDenied
        request.session['register_auth'] = False

        return render(request, 'users/success.html')
    
        
       
class RegisterView(CsRegisterView):
    template_name = 'users/register.html'
    form_class = RegisterForm


def success(request):
    return render(request, 'users/success.html')




  