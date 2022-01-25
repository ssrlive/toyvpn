/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ssrlive.toyvpn;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class ToyVpnClient extends Activity {
    public interface Prefs {
        String NAME = "connection";
        String SERVER_ADDRESS = "server.address";
        String SERVER_PORT = "server.port";
        String SHARED_SECRET = "shared.secret";
        String PROXY_HOSTNAME = "proxyhost";
        String PROXY_PORT = "proxyport";
        String ALLOW = "allow";
        String PACKAGES = "packages";
    }

    TextView serverAddress;
    TextView serverPort;
    TextView sharedSecret;
    TextView proxyHost;
    TextView proxyPort;

    RadioButton allowed;
    TextView packages;

    SharedPreferences prefs;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.form);

        serverAddress = findViewById(R.id.address);
        serverPort = findViewById(R.id.port);
        sharedSecret = findViewById(R.id.secret);
        proxyHost = findViewById(R.id.proxyhost);
        proxyPort = findViewById(R.id.proxyport);

        allowed = findViewById(R.id.allowed);
        packages = findViewById(R.id.packages);

        prefs = getSharedPreferences(Prefs.NAME, MODE_PRIVATE);

        findViewById(R.id.connect).setOnClickListener(v -> {
            String sProxyHost = proxyHost.getText().toString();
            String sProxyPort = proxyPort.getText().toString();
            if (!checkProxyConfigs(sProxyHost, sProxyPort)) {
                return;
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                final Set<String> packageSet =
                        Arrays.stream(packages.getText().toString().split(","))
                                .map(String::trim)
                                .filter(s -> !s.isEmpty())
                                .collect(Collectors.toSet());
                if (!checkPackages(packageSet)) {
                    return;
                }
            }

            Intent intent = VpnService.prepare(ToyVpnClient.this);
            if (intent != null) {
                startActivityForResult(intent, 0);
            } else {
                doStartVpnService();
            }
        });
        findViewById(R.id.disconnect).setOnClickListener(v -> {
            startService(getVpnServiceIntent().setAction(ToyVpnService.ACTION_DISCONNECT));
        });

        restoreDataFromPreferences();
    }

    private void doStartVpnService() {
        startService(getVpnServiceIntent().setAction(ToyVpnService.ACTION_CONNECT));
    }

    private Intent getVpnServiceIntent() {
        return new Intent(this, ToyVpnService.class);
    }

    @Override
    public void onRestoreInstanceState(Bundle savedInstanceState) {
        // super.onRestoreInstanceState(savedInstanceState);
        restoreDataFromPreferences();
    }

    private void restoreDataFromPreferences() {
        serverAddress.setText(prefs.getString(Prefs.SERVER_ADDRESS, ""));
        int serverPortPrefValue = prefs.getInt(Prefs.SERVER_PORT, 0);
        serverPort.setText(String.valueOf(serverPortPrefValue == 0 ? "" : serverPortPrefValue));
        sharedSecret.setText(prefs.getString(Prefs.SHARED_SECRET, ""));
        proxyHost.setText(prefs.getString(Prefs.PROXY_HOSTNAME, ""));
        int proxyPortPrefValue = prefs.getInt(Prefs.PROXY_PORT, 0);
        proxyPort.setText(proxyPortPrefValue == 0 ? "" : String.valueOf(proxyPortPrefValue));

        allowed.setChecked(prefs.getBoolean(Prefs.ALLOW, true));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            packages.setText(String.join(", ", prefs.getStringSet(
                    Prefs.PACKAGES, Collections.emptySet())));
        }
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        int serverPortNum = 0, proxyPortNum = 0;
        try {
            String str = serverPort.getText().toString();
            serverPortNum = Integer.parseInt(str.length() > 0 ? str : "0");
            str = proxyPort.getText().toString();
            proxyPortNum = Integer.parseInt(str.length() > 0 ? str : "0");
        } catch (NumberFormatException e) {
            e.printStackTrace();
        }
        Set<String> packageSet = new HashSet<String>();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            packageSet = Arrays.stream(packages.getText().toString().split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toSet());
        }
        prefs.edit()
                .putString(Prefs.SERVER_ADDRESS, serverAddress.getText().toString())
                .putInt(Prefs.SERVER_PORT, serverPortNum)
                .putString(Prefs.SHARED_SECRET, sharedSecret.getText().toString())
                .putString(Prefs.PROXY_HOSTNAME, proxyHost.getText().toString())
                .putInt(Prefs.PROXY_PORT, proxyPortNum)
                .putBoolean(Prefs.ALLOW, allowed.isChecked())
                .putStringSet(Prefs.PACKAGES, packageSet)
                .apply();
    }

    private boolean checkProxyConfigs(String proxyHost, String proxyPort) {
        final boolean hasIncompleteProxyConfigs = proxyHost.isEmpty() != proxyPort.isEmpty();
        if (hasIncompleteProxyConfigs) {
            Toast.makeText(this, R.string.incomplete_proxy_settings, Toast.LENGTH_SHORT).show();
        }
        return !hasIncompleteProxyConfigs;
    }

    @TargetApi(Build.VERSION_CODES.N)
    private boolean checkPackages(Set<String> packageNames) {
        final boolean hasCorrectPackageNames = packageNames.isEmpty() ||
                getPackageManager().getInstalledPackages(0).stream()
                        .map(pi -> pi.packageName)
                        .collect(Collectors.toSet())
                        .containsAll(packageNames);
        if (!hasCorrectPackageNames) {
            Toast.makeText(this, R.string.unknown_package_names, Toast.LENGTH_SHORT).show();
        }
        return hasCorrectPackageNames;
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (result == RESULT_OK) {
            doStartVpnService();
        }
    }
}
