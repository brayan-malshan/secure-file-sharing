from datetime import datetime
from models import FilePermission


def get_permission(file, user):
    """Returns the FilePermission row for (file, user), or None."""
    return FilePermission.query.filter_by(file_id=file.id, user_id=user.id).first()


def user_can_access(file, user):
    """
    Access rule:
      - Trashed files are only reachable by their owner (for restore).
      - Owner always has access.
      - A shared recipient has access only if a non-expired, non-exhausted
        FilePermission row exists for them.
    """
    if file.is_trashed and file.owner_id != user.id:
        return False, "trashed"

    if file.owner_id == user.id:
        return True, None

    perm = get_permission(file, user)
    if perm is None:
        return False, "no_permission"
    if perm.is_expired():
        return False, "expired_or_exhausted"
    return True, perm


def revoke_access(file, user_id):
    perm = FilePermission.query.filter_by(file_id=file.id, user_id=user_id).first()
    if perm:
        from models import db
        db.session.delete(perm)
        db.session.commit()
        return True
    return False
