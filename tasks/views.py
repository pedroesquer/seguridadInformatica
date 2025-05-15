from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.db import IntegrityError
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import never_cache
from Crypto.Cipher import AES
import base64
import hashlib


def home(request):
    return render(request, 'home.html')


def signup(request):
    if request.method == 'GET':
        return render(request, 'signup.html', {'form': UserCreationForm()})
    else:
        form = UserCreationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                login(request, user)
                return redirect('tasks')
            except IntegrityError:
                form.add_error('username', 'Username already exists')
        # Si no es válido o capturamos IntegrityError, volvemos a mostrar el form con errores
        return render(request, 'signup.html', {'form': form})


@never_cache
@login_required
def tasks(request):
    request.session['visited_tasks'] = True
    return render(request, 'tasks.html')


def signout(request):
    logout(request)
    return redirect('home')


def signin(request):
    if request.method == 'GET':
        return render(request, 'signin.html', {'form': AuthenticationForm()})
    else:
        user = authenticate(
            request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'signin.html', {'form': AuthenticationForm(), 'error': 'Invalid username or password'})
        else:
            login(request, user)
            return redirect('tasks')


def invalidate_session(request):
    logout(request)
    return redirect('signin')


def pad(texto):
    while len(texto) % 16 != 0:
        texto += ' '
    return texto


@login_required
def encrypt_view(request):
    if request.method == 'POST':
        texto = request.POST['texto']
        clave_usuario = request.POST['clave']

        if not clave_usuario:
            return render(request, 'encrypt.html', {'resultado': 'Debes ingresar una clave para cifrar.'})

        key_bytes = hashlib.sha256(clave_usuario.encode()).digest()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        texto_padded = pad(texto)
        encrypted_bytes = cipher.encrypt(texto_padded.encode('utf-8'))
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
        return render(request, 'encrypt.html', {'resultado': encrypted_b64})

    return render(request, 'encrypt.html')


@login_required
def decrypt_view(request):
    if request.method == 'POST':
        texto_cifrado = request.POST['texto']
        clave_usuario = request.POST['clave']


        if not clave_usuario:
            return render(request, 'decrypt.html', {'resultado': 'Debes ingresar la misma clave con la que fue cifrado.'})

        key_bytes = hashlib.sha256(clave_usuario.encode()).digest()
        key_bytes = hashlib.sha256(clave_usuario.encode()).digest()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        try:
            decoded = base64.b64decode(texto_cifrado)
            decrypted_bytes = cipher.decrypt(decoded)
            texto_descifrado = decrypted_bytes.decode('utf-8').rstrip()
            return render(request, 'decrypt.html', {'resultado': texto_descifrado})
        except:
            return render(request, 'decrypt.html', {'resultado': 'Error al descifrar. Verifica el texto o la clave.'})
    
    return render(request, 'decrypt.html')

    