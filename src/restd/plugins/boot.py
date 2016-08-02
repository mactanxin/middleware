from base import CRUDBase, SingleItemBase


class BootPoolItem(SingleItemBase):
    namespace = 'boot.pool'

    def get_update_method_name(self):
        # This namespace has no update method
        return None


class BootEnvironmentItem(CRUDBase):
    namespace = 'boot.environment'


def _init(rest):
    rest.register_singleitem(BootPoolItem)
    rest.register_crud(BootEnvironmentItem)
