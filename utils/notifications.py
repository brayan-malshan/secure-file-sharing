from models import db, Notification


def notify(user, message, category="info", link=None):
    """Create an in-app notification for a user. Silently no-ops if user is None."""
    if user is None:
        return
    db.session.add(Notification(
        user_id=user.id, message=message, category=category, link=link,
    ))
    db.session.commit()


def unread_count(user):
    if user is None or not user.is_authenticated:
        return 0
    return Notification.query.filter_by(user_id=user.id, is_read=False).count()
