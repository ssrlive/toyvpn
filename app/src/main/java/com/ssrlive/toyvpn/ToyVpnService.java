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
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class ToyVpnService extends VpnService {
    private static final String TAG = ToyVpnService.class.getSimpleName();

    public static final String ACTION_CONNECT = "com.ssrlive.toyvpn.START";
    public static final String ACTION_DISCONNECT = "com.ssrlive.toyvpn.STOP";

    private Handler mHandler;

    private final AtomicReference<Thread> mVpnThread = new AtomicReference<>();
    private final AtomicInteger mNextConnectionId = new AtomicInteger(1);

    private PendingIntent mConfigureIntent;

    @Override
    public void onCreate() {
        Log.i(TAG, "onCreate");
        // The handler is only used to show messages.
        if (mHandler == null) {
            //noinspection deprecation
            mHandler = new Handler(new Handler.Callback() {
                @Override
                public boolean handleMessage(Message msg) {
                    Toast.makeText(ToyVpnService.this, msg.what, Toast.LENGTH_SHORT).show();
                    if (msg.what != R.string.ending) {
                        // Become a foreground service. Background services can be VPN services too, but they can
                        // be killed by background check before getting a chance to receive onRevoke().
                        updateForegroundNotification(msg.what);
                    } else {
                        stopForeground(true);
                    }
                    return true;
                }
            });
        }

        // Create the intent to "configure" the connection (just start ToyVpnClient).
        mConfigureIntent = PendingIntent.getActivity(this, 0, new Intent(this, ToyVpnClient.class),
                PendingIntent.FLAG_UPDATE_CURRENT);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent.getAction();
        Log.i(TAG, "onStartCommand with action " + action);
        if (ACTION_DISCONNECT.equals(action)) {
            disconnect();
            return START_NOT_STICKY;
        } else {
            connect();
            return START_STICKY;
        }
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "onDestroy");
        disconnect();
    }

    private void connect() {
        // Extract information from the shared preferences.
        final SharedPreferences prefs = getSharedPreferences(ToyVpnClient.Prefs.NAME, MODE_PRIVATE);
        final String server = prefs.getString(ToyVpnClient.Prefs.SERVER_ADDRESS, "");
        final byte[] secret = prefs.getString(ToyVpnClient.Prefs.SHARED_SECRET, "").getBytes();
        final boolean allow = prefs.getBoolean(ToyVpnClient.Prefs.ALLOW, true);
        final Set<String> packages =
                prefs.getStringSet(ToyVpnClient.Prefs.PACKAGES, Collections.emptySet());
        final int port = prefs.getInt(ToyVpnClient.Prefs.SERVER_PORT, 0);
        final String proxyHost = prefs.getString(ToyVpnClient.Prefs.PROXY_HOSTNAME, "");
        final int proxyPort = prefs.getInt(ToyVpnClient.Prefs.PROXY_PORT, 0);
        startToyVpnRunnable(new ToyVpnRunnable(
                this, mNextConnectionId.getAndIncrement(), server, port, secret,
                proxyHost, proxyPort, allow, packages));
    }

    private void startToyVpnRunnable(final ToyVpnRunnable runnable) {
        // Replace any existing connecting thread with the  new one.
        final Thread thread = new Thread(runnable, "ToyVpnThread");
        storeConnectingThread(thread);

        // Handler to mark as connected once onEstablish is called.
        runnable.setConfigureIntent(mConfigureIntent);
        runnable.setOnConnectListener(
                new ToyVpnRunnable.OnConnectListener() {
                    @Override
                    public void onTaskLaunch() {
                        mHandler.sendEmptyMessage(R.string.launching);
                    }

                    @Override
                    public void onConnecting() {
                        mHandler.sendEmptyMessage(R.string.connecting);
                    }

                    @Override
                    public void onEstablish(ParcelFileDescriptor tunInterface) {
                        mHandler.sendEmptyMessage(R.string.connected);
                    }

                    @Override
                    public void onDisconnected() {
                        mHandler.sendEmptyMessage(R.string.disconnected);
                    }

                    @Override
                    public void onTaskTerminate() {
                        mHandler.sendEmptyMessage(R.string.ending);
                    }
                });
        thread.start();
    }

    private void storeConnectingThread(final Thread thread) {
        final Thread oldThread = mVpnThread.getAndSet(thread);
        if (oldThread != null) {
            oldThread.interrupt();
        }
    }

    private void disconnect() {
        storeConnectingThread(null);
    }

    @TargetApi(Build.VERSION_CODES.O)
    private void updateForegroundNotification(final int message) {
        final String CHANNEL_ID = "ToyVpn";
        NotificationChannel channel;
        channel = new NotificationChannel(CHANNEL_ID, CHANNEL_ID, NotificationManager.IMPORTANCE_DEFAULT);
        NotificationManager mgr = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        mgr.createNotificationChannel(channel);
        startForeground(1, new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentText(getString(message))
                .setContentIntent(mConfigureIntent)
                .build());
    }
}
