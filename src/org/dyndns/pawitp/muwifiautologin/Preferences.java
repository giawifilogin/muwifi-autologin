package org.dyndns.pawitp.muwifiautologin;

import java.util.ArrayList;
import java.util.Iterator;

import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.widget.BaseAdapter;

public class Preferences extends PreferenceActivity implements OnSharedPreferenceChangeListener {
	static final String KEY_LOGIN_NOW = "login_now";
	static final String KEY_ENABLED = "enabled";
	static final String KEY_USERNAME = "username";
	static final String KEY_PASSWORD = "password";
	static final String KEY_VERSION = "version";
	static final String KEY_ERROR_NOTIFY = "error_notify";
	static final String KEY_ERROR_NOTIFY_SOUND = "error_notify_sound";
	static final String KEY_ERROR_NOTIFY_VIBRATE = "error_notify_vibrate";
	static final String KEY_ERROR_NOTIFY_LIGHTS = "error_notify_lights";
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.preferences);
        
        updateUsernameSummary();
        updateErrorNotificationSummary();
        
        // Set version number
		try {
			String versionSummary = String.format(getString(R.string.pref_version_summary), getPackageManager().getPackageInfo(getPackageName(), 0).versionName);
			findPreference(KEY_VERSION).setSummary(versionSummary);
		} catch (NameNotFoundException e) {
			// kind of impossible
		}
		
		// Login now callback
		findPreference(KEY_LOGIN_NOW).setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
			@Override
			public boolean onPreferenceClick(Preference preference) {
				MuWifiLogin login = new MuWifiLogin(Preferences.this, getPreferenceManager().getSharedPreferences());
				login.login();
				return true;
			}
		});
    }

	@Override
	protected void onResume() {
		super.onResume();

		// Callback to update dynamic summaries when they get changed
		getPreferenceScreen().getSharedPreferences().registerOnSharedPreferenceChangeListener(this);
	}
	
	@Override
	protected void onPause() {
		super.onPause();
		getPreferenceScreen().getSharedPreferences().unregisterOnSharedPreferenceChangeListener(this);
	}

	@Override
	public void onSharedPreferenceChanged(SharedPreferences sharedPreferences,
			String key) {
		if (key.equals(KEY_USERNAME)) {
			updateUsernameSummary();
		}
		else if (key.equals(KEY_ERROR_NOTIFY_SOUND)
				|| key.equals(KEY_ERROR_NOTIFY_VIBRATE)
				|| key.equals(KEY_ERROR_NOTIFY_LIGHTS)) {
			updateErrorNotificationSummary();
			((BaseAdapter) getPreferenceScreen().getRootAdapter()).notifyDataSetChanged(); // force update parent screen
		}
	}
	
	private void updateUsernameSummary() {
		// Set username as summary if set
        String username = getPreferenceManager().getSharedPreferences().getString(KEY_USERNAME, "");
        if (username.length() != 0) {
        	findPreference(KEY_USERNAME).setSummary(username);
        } else {
        	findPreference(KEY_USERNAME).setSummary(R.string.pref_username_summary);
        }
	}
	
	private void updateErrorNotificationSummary() {
		ArrayList<String> methods = new ArrayList<String>();
		
		SharedPreferences prefs = getPreferenceManager().getSharedPreferences();
		
		if (prefs.getBoolean(Preferences.KEY_ERROR_NOTIFY_SOUND, false)) {
			methods.add(getString(R.string.pref_error_notify_sound));
		}
		if (prefs.getBoolean(Preferences.KEY_ERROR_NOTIFY_VIBRATE, false)) {
			methods.add(getString(R.string.pref_error_notify_vibrate));
		}
		if (prefs.getBoolean(Preferences.KEY_ERROR_NOTIFY_LIGHTS, false)) {
			methods.add(getString(R.string.pref_error_notify_lights));
		}
		
		if (methods.size() == 0) {
			findPreference(KEY_ERROR_NOTIFY).setSummary(R.string.pref_error_notify_none);
		}
		else {
			StringBuilder sb = new StringBuilder();
			Iterator<String> iter = methods.iterator();
			
			sb.append(iter.next());
			while (iter.hasNext()) {
				sb.append(getString(R.string.pref_error_notify_deliminator));
				sb.append(iter.next());
			}
			
			findPreference(KEY_ERROR_NOTIFY).setSummary(sb);
		}
	}
}