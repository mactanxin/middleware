from base import CRUDTestCase, RESTTestCase


class AlertTestCase(RESTTestCase):
    name = 'alert'

    def test_020_retrieve(self):
        r = self.client.get(self.name)
        self.assertEqual(r.status_code, 200, msg=r.text)
        data = r.json()
        self.assertIsInstance(data, list)

    def test_021_get_alert_classes(self):
        r = self.client.get(self.name + '/get_alert_classes')
        self.assertEqual(r.status_code, 200, msg=r.text)
        data = r.json()
        self.assertIsInstance(data, list)

    def test_022_send(self):
        r = self.client.post(self.name + '/send', data=[
            'test!',
            'INFO',
        ])
        self.assertEqual(r.status_code, 201, msg=r.text)


class AlertFilterTestCase(CRUDTestCase):
    name = 'alert/filter'

    def get_create_data(self):
        return {
            'id': 'alertfiltertest',
            'emitter': 'EMAIL',
            'parameters': {
                'addresses': ['freenas@ixsystems.com']
            }
        }

    def get_update_ident_data(self):
        return 'alertfiltertest', {
            'predicates': [
                {
                    'property': 'clazz',
                    'operator': '==',
                    'value': 'VolumeUpgradePossible',
                }
            ]
        }

    def get_delete_identifier(self):
        return 'alertfiltertest'
