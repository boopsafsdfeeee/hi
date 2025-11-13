admin
list_display = ('client_id', 'last_seen', 'is_active', 'action_send_command', 'action_reverse_shell', 'action_file_manager')


    @admin.display(description='파일 관리자')
    def action_file_manager(self, obj):
        url = reverse("file_manager_root", args=[obj.client_id])
        return mark_safe(f'<a class="button" href="{url}" target="_blank">파일 관리자</a>')

views.
from django.shortcuts import render, redirect, get_object_or_404

urls
import re_path

    path('file_manager/<str:client_id>/', views.file_manager_view, name='file_manager_root'), 
    
    # Deep path (handles the '::' path separator)
    re_path(r'^file_manager/(?P<client_id>[^/]+)/(?P<requested_path>.*)$', 
            views.file_manager_view, 
            name='file_manager_deep'), 


├── tasks/templates
│   └── /tasks
│       └── file_manager.html

tasks/templatetags/custom_filters.py
