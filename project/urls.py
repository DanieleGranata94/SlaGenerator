"""threat-modeling URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from SlaGenerator import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',  views.apps_management, name='apps_management'),
    path('asset_management/<int:appId>', views.asset_management, name='asset_management'),
    path('threat_modeling/<int:appId>/<int:assetId>', views.threat_modeling_per_asset, name='threat_modeling_per_asset'),
    path('threat_modeling/<int:appId>', views.threat_modeling, name='threat_modeling'),
    path('calculate_threat_agent_risks/<int:appId>', views.calculate_threat_agent_risks, name='calculate_threat_agent_risks'),
    path('export_threat_modeling/<int:appId>', views.export_threat_modeling, name='export_threat_modeling'),
    path('threat_agent_wizard/<int:appId>', views.threat_agent_wizard, name='threat_agent_wizard'),
    path('risk_analysis/<int:appId>', views.risk_analysis, name='risk_analysis'),
    path('stride_impact_evaluation/<int:appId>', views.stride_impact_evaluation, name='stride_impact_evaluation'),
    path('stride_impact_evaluation_menu/<int:appId>', views.stride_impact_evaluation_menu, name='stride_impact_evaluation_menu'),
    path('threat_modeling_menu/<int:appId>', views.threat_modeling_menu, name='threat_modeling_menu'),
    path('threat_agent_generation/<int:appId>', views.threat_agent_generation, name='threat_agent_generation'),
    path('macm_viewer/<int:appId>', views.macm_viewer, name='macm_viewer'),

]
