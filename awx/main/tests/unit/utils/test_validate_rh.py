from unittest.mock import patch
from awx.main.utils.licensing import Licenser


def test_validate_rh_basic_auth_rhsm():
    """
    Assert get_rhsm_subs is called when
    - basic_auth=True
    - host is subscription.rhsm.redhat.com
    """
    licenser = Licenser()

    with patch.object(licenser, 'get_host_from_rhsm_config', return_value='https://subscription.rhsm.redhat.com') as mock_get_host, patch.object(
        licenser, 'get_rhsm_subs', return_value=[]
    ) as mock_get_rhsm, patch.object(licenser, 'get_satellite_subs') as mock_get_satellite, patch.object(
        licenser, 'get_crc_subs'
    ) as mock_get_crc, patch.object(
        licenser, 'generate_license_options_from_entitlements'
    ) as mock_generate:

        licenser.validate_rh('testuser', 'testpass', basic_auth=True)

        # Assert the correct methods were called
        mock_get_host.assert_called_once()
        mock_get_rhsm.assert_called_once_with('https://subscription.rhsm.redhat.com', 'testuser', 'testpass')
        mock_get_satellite.assert_not_called()
        mock_get_crc.assert_not_called()
        mock_generate.assert_called_once_with([], is_candlepin=True)


def test_validate_rh_basic_auth_satellite():
    """
    Assert get_satellite_subs is called when
    - basic_auth=True
    - custom satellite host
    """
    licenser = Licenser()

    with patch.object(licenser, 'get_host_from_rhsm_config', return_value='https://satellite.example.com') as mock_get_host, patch.object(
        licenser, 'get_rhsm_subs'
    ) as mock_get_rhsm, patch.object(licenser, 'get_satellite_subs', return_value=[]) as mock_get_satellite, patch.object(
        licenser, 'get_crc_subs'
    ) as mock_get_crc, patch.object(
        licenser, 'generate_license_options_from_entitlements'
    ) as mock_generate:

        licenser.validate_rh('testuser', 'testpass', basic_auth=True)

        # Assert the correct methods were called
        mock_get_host.assert_called_once()
        mock_get_rhsm.assert_not_called()
        mock_get_satellite.assert_called_once_with('https://satellite.example.com', 'testuser', 'testpass')
        mock_get_crc.assert_not_called()
        mock_generate.assert_called_once_with([], is_candlepin=True)


def test_validate_rh_service_account_crc():
    """
    Assert get_crc_subs is called when
    - basic_auth=False
    - REDHAT_CANDLEPIN_HOST is not set
    """
    licenser = Licenser()

    with patch('awx.main.utils.licensing.settings') as mock_settings, patch.object(licenser, 'get_host_from_rhsm_config') as mock_get_host, patch.object(
        licenser, 'get_rhsm_subs'
    ) as mock_get_rhsm, patch.object(licenser, 'get_satellite_subs') as mock_get_satellite, patch.object(
        licenser, 'get_crc_subs', return_value=[]
    ) as mock_get_crc, patch.object(
        licenser, 'generate_license_options_from_entitlements'
    ) as mock_generate:

        mock_settings.REDHAT_CANDLEPIN_HOST = None
        mock_settings.SUBSCRIPTIONS_RHSM_URL = 'https://console.redhat.com/api/rhsm/v1/subscriptions'

        licenser.validate_rh('client_id', 'client_secret', basic_auth=False)

        # Assert the correct methods were called
        mock_get_host.assert_not_called()
        mock_get_rhsm.assert_not_called()
        mock_get_satellite.assert_not_called()
        mock_get_crc.assert_called_once_with('https://console.redhat.com/api/rhsm/v1/subscriptions', 'client_id', 'client_secret')
        mock_generate.assert_called_once_with([], is_candlepin=False)


def test_validate_rh_missing_user_raises_error():
    """Test validate_rh raises ValueError when user is missing"""
    licenser = Licenser()

    with patch.object(licenser, 'get_host_from_rhsm_config', return_value='https://subscription.rhsm.redhat.com'):
        try:
            licenser.validate_rh(None, 'testpass', basic_auth=True)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'subscriptions_client_id or subscriptions_username is required' in str(e)


def test_validate_rh_missing_password_raises_error():
    """Test validate_rh raises ValueError when password is missing"""
    licenser = Licenser()

    with patch.object(licenser, 'get_host_from_rhsm_config', return_value='https://subscription.rhsm.redhat.com'):
        try:
            licenser.validate_rh('testuser', None, basic_auth=True)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'subscriptions_client_secret or subscriptions_password is required' in str(e)


def test_validate_rh_candlepin_host_used_when_set():
    """Test validate_rh uses REDHAT_CANDLEPIN_HOST when it is set.

    REDHAT_CANDLEPIN_HOST is checked first as an explicit admin override,
    so get_host_from_rhsm_config is never consulted.
    - basic_auth=True
    - REDHAT_CANDLEPIN_HOST is set
    """
    licenser = Licenser()

    with patch('awx.main.utils.licensing.settings') as mock_settings, patch.object(licenser, 'get_host_from_rhsm_config') as mock_get_host, patch.object(
        licenser, 'get_rhsm_subs', return_value=[]
    ) as mock_get_rhsm, patch.object(licenser, 'get_satellite_subs', return_value=[]) as mock_get_satellite, patch.object(
        licenser, 'get_crc_subs'
    ) as mock_get_crc, patch.object(
        licenser, 'generate_license_options_from_entitlements'
    ) as mock_generate:

        mock_settings.REDHAT_CANDLEPIN_HOST = 'https://candlepin.example.com'
        licenser.validate_rh('testuser', 'testpass', basic_auth=True)

        # REDHAT_CANDLEPIN_HOST takes priority; rhsm.conf is not consulted
        mock_get_host.assert_not_called()
        mock_get_rhsm.assert_not_called()
        mock_get_satellite.assert_called_once_with('https://candlepin.example.com', 'testuser', 'testpass')
        mock_get_crc.assert_not_called()
        mock_generate.assert_called_once_with([], is_candlepin=True)


def test_validate_rh_empty_credentials_basic_auth():
    """Test validate_rh with empty string credentials raises ValueError"""
    licenser = Licenser()

    with patch.object(licenser, 'get_host_from_rhsm_config', return_value='https://subscription.rhsm.redhat.com'):
        # Test empty user
        try:
            licenser.validate_rh(None, 'testpass', basic_auth=True)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'subscriptions_client_id or subscriptions_username is required' in str(e)

        # Test empty password
        try:
            licenser.validate_rh('testuser', None, basic_auth=True)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'subscriptions_client_secret or subscriptions_password is required' in str(e)


def test_validate_rh_candlepin_host_priority_over_rhsm_conf():
    """Regression test for AAP-76460: REDHAT_CANDLEPIN_HOST must take priority over rhsm.conf.

    When REDHAT_CANDLEPIN_HOST is set (admin configured Satellite) AND rhsm.conf
    returns a valid host (subscription.rhsm.redhat.com), REDHAT_CANDLEPIN_HOST
    should win and get_satellite_subs should be called -- not get_rhsm_subs.
    """
    licenser = Licenser()

    with patch('awx.main.utils.licensing.settings') as mock_settings, patch.object(
        licenser, 'get_host_from_rhsm_config', return_value='https://subscription.rhsm.redhat.com'
    ) as mock_get_host, patch.object(licenser, 'get_rhsm_subs') as mock_get_rhsm, patch.object(
        licenser, 'get_satellite_subs', return_value=[]
    ) as mock_get_satellite, patch.object(
        licenser, 'get_crc_subs'
    ) as mock_get_crc, patch.object(
        licenser, 'generate_license_options_from_entitlements'
    ) as mock_generate:

        mock_settings.REDHAT_CANDLEPIN_HOST = 'https://satellite.example.com'
        licenser.validate_rh('testuser', 'testpass', basic_auth=True)

        # REDHAT_CANDLEPIN_HOST takes priority; rhsm.conf is never consulted
        mock_get_host.assert_not_called()
        mock_get_rhsm.assert_not_called()
        mock_get_satellite.assert_called_once_with('https://satellite.example.com', 'testuser', 'testpass')
        mock_get_crc.assert_not_called()
        mock_generate.assert_called_once_with([], is_candlepin=True)


def test_validate_rh_candlepin_host_used_as_host_with_service_account():
    """REDHAT_CANDLEPIN_HOST is used as the host URL even when basic_auth=False.

    The host resolution respects REDHAT_CANDLEPIN_HOST regardless of auth method,
    but the dispatch logic still uses basic_auth to decide which API method to call.
    When basic_auth=False, get_crc_subs is called with the candlepin host.
    """
    licenser = Licenser()

    with patch('awx.main.utils.licensing.settings') as mock_settings, patch.object(licenser, 'get_host_from_rhsm_config') as mock_get_host, patch.object(
        licenser, 'get_rhsm_subs'
    ) as mock_get_rhsm, patch.object(licenser, 'get_satellite_subs') as mock_get_satellite, patch.object(
        licenser, 'get_crc_subs', return_value=[]
    ) as mock_get_crc, patch.object(
        licenser, 'generate_license_options_from_entitlements'
    ) as mock_generate:

        mock_settings.REDHAT_CANDLEPIN_HOST = 'https://satellite.example.com'
        mock_settings.SUBSCRIPTIONS_RHSM_URL = 'https://console.redhat.com/api/rhsm/v1/subscriptions'
        licenser.validate_rh('client_id', 'client_secret', basic_auth=False)

        # REDHAT_CANDLEPIN_HOST provides the host, but basic_auth=False means CRC dispatch
        mock_get_host.assert_not_called()
        mock_get_rhsm.assert_not_called()
        mock_get_satellite.assert_not_called()
        mock_get_crc.assert_called_once_with('https://satellite.example.com', 'client_id', 'client_secret')
        mock_generate.assert_called_once_with([], is_candlepin=False)


def test_validate_rh_no_candlepin_host_falls_through_to_rhsm_conf():
    """When REDHAT_CANDLEPIN_HOST is not set, basic_auth=True falls through to rhsm.conf."""
    licenser = Licenser()

    with patch.object(licenser, 'get_host_from_rhsm_config', return_value='https://subscription.rhsm.redhat.com') as mock_get_host, patch.object(
        licenser, 'get_rhsm_subs', return_value=[]
    ) as mock_get_rhsm, patch.object(licenser, 'get_satellite_subs') as mock_get_satellite, patch.object(
        licenser, 'get_crc_subs'
    ) as mock_get_crc, patch.object(
        licenser, 'generate_license_options_from_entitlements'
    ) as mock_generate:

        licenser.validate_rh('testuser', 'testpass', basic_auth=True)

        # rhsm.conf is consulted because REDHAT_CANDLEPIN_HOST is not set
        mock_get_host.assert_called_once()
        mock_get_rhsm.assert_called_once_with('https://subscription.rhsm.redhat.com', 'testuser', 'testpass')
        mock_get_satellite.assert_not_called()
        mock_get_crc.assert_not_called()
        mock_generate.assert_called_once_with([], is_candlepin=True)


def test_validate_rh_no_host_raises_error():
    """When no host source provides a value, ValueError is raised."""
    licenser = Licenser()

    with patch('awx.main.utils.licensing.settings') as mock_settings, patch.object(licenser, 'get_host_from_rhsm_config', return_value=None):
        mock_settings.REDHAT_CANDLEPIN_HOST = None
        try:
            licenser.validate_rh('testuser', 'testpass', basic_auth=True)
            assert False, "Expected ValueError to be raised"
        except ValueError as e:
            assert 'Could not get host url for subscriptions' in str(e)
