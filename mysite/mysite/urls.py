from django.contrib import admin
from django.urls import path
from scanner import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home),
    path('scan/', views.scan),
    path('ai-chat/', views.ai_chat),
]