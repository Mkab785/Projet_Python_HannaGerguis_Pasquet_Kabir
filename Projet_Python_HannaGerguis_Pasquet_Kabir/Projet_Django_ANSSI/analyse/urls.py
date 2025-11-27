from django.urls import path
from . import views


urlpatterns = [
    path('', views.page_principale, name='page_principale'),
    path('resultats/', views.afficher_resultats, name='resultats'),
    path('jupyter_notebook/', views.afficher_jupyter_notebook, name='jupyter_notebook'),
    path('informations/', views.afficher_informations, name= 'informations'),

]