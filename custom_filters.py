from django import template
import os

register = template.Library()

@register.filter
def path_join(path1, path2):
    """Joins two path components using '/' and cleans up double slashes."""
    # Use '/' for web paths, replace '::' with '/'
    joined = os.path.join(path1.replace('::', '/'), path2).replace('\\', '/')
    # Handle the '..' case for parent directory navigation
    if path2 == '..':
        return os.path.dirname(joined).rstrip('/')
    return joined

@register.filter
def dirname(path):
    """Gets the parent directory of a path."""
    path = path.replace('::', '/')
    # Get the directory name, then clean up trailing separators and get the dirname again for the parent
    parent_path = os.path.dirname(path.rstrip('/'))
    # If we are at C:/ or D:/, this should return the root itself
    if len(parent_path) < 3 and parent_path.endswith(':'): 
         return parent_path
         
    return parent_path.replace('\\', '/')