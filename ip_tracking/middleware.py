from .models import RequestLog, BlockedIP
from django.http import HttpResponseForbidden


class IPTrackingMiddleware:
    """
    Middleware to log IP address, path, and timestamp of incoming requests.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Log to database
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path
        )

        # Continue processing request
        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """
        Retrieves the client's IP address from the request.
        Handles cases where a reverse proxy might be used.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # X-Forwarded-For can contain multiple IPs; take the first one
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip    


class BlockedIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: Your IP has been blocked.")

        return self.get_response(request)

    def get_client_ip(self, request):
        """Try to get the real IP address even behind proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

