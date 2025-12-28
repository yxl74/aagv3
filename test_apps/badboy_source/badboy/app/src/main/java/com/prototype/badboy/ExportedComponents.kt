package com.prototype.badboy

import android.app.Activity
import android.app.Service
import android.content.BroadcastReceiver
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.os.IBinder

// EXPORTED ACTIVITIES
class ExportedLoginActivity : Activity() { override fun onCreate(s: Bundle?) { super.onCreate(s); finish() } }
class ExportedPaymentActivity : Activity() { override fun onCreate(s: Bundle?) { super.onCreate(s); finish() } }
class ExportedSettingsActivity : Activity() { override fun onCreate(s: Bundle?) { super.onCreate(s); finish() } }
class ExportedDebugActivity : Activity() { override fun onCreate(s: Bundle?) { super.onCreate(s); finish() } }
class ExportedAdminActivity : Activity() { override fun onCreate(s: Bundle?) { super.onCreate(s); finish() } }
class ExportedTransferActivity : Activity() { override fun onCreate(s: Bundle?) { super.onCreate(s); finish() } }
class ExportedWebViewActivity : Activity() { override fun onCreate(s: Bundle?) { super.onCreate(s); finish() } }
class ExportedDeepLinkActivity : Activity() { override fun onCreate(s: Bundle?) { super.onCreate(s); finish() } }
class ExportedFileActivity : Activity() { override fun onCreate(s: Bundle?) { super.onCreate(s); finish() } }

// EXPORTED SERVICES
class ExportedDataService : Service() { override fun onBind(i: Intent?): IBinder? = null }
class ExportedSyncService : Service() { override fun onBind(i: Intent?): IBinder? = null }
class ExportedUploadService : Service() { override fun onBind(i: Intent?): IBinder? = null }
class ExportedDownloadService : Service() { override fun onBind(i: Intent?): IBinder? = null }
class ExportedCommandService : Service() { override fun onBind(i: Intent?): IBinder? = null }
class ExportedRemoteService : Service() { override fun onBind(i: Intent?): IBinder? = null }
class ExportedBackgroundService : Service() { override fun onBind(i: Intent?): IBinder? = null }
class ExportedMessagingService : Service() { override fun onBind(i: Intent?): IBinder? = null }

// EXPORTED RECEIVERS
class ExportedCommandReceiver : BroadcastReceiver() { override fun onReceive(c: Context?, i: Intent?) {} }
class ExportedUpdateReceiver : BroadcastReceiver() { override fun onReceive(c: Context?, i: Intent?) {} }
class ExportedTriggerReceiver : BroadcastReceiver() { override fun onReceive(c: Context?, i: Intent?) {} }
class ExportedPushReceiver : BroadcastReceiver() { override fun onReceive(c: Context?, i: Intent?) {} }
class ExportedWakeReceiver : BroadcastReceiver() { override fun onReceive(c: Context?, i: Intent?) {} }
class ExportedPackageReceiver : BroadcastReceiver() { override fun onReceive(c: Context?, i: Intent?) {} }
class ExportedNetworkReceiver : BroadcastReceiver() { override fun onReceive(c: Context?, i: Intent?) {} }
class ExportedBatteryReceiver : BroadcastReceiver() { override fun onReceive(c: Context?, i: Intent?) {} }

// EXPORTED CONTENT PROVIDERS
abstract class StubProvider : ContentProvider() {
    override fun onCreate() = true
    override fun query(u: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? = null
    override fun getType(u: Uri): String? = null
    override fun insert(u: Uri, v: ContentValues?): Uri? = null
    override fun delete(u: Uri, s: String?, a: Array<String>?) = 0
    override fun update(u: Uri, v: ContentValues?, s: String?, a: Array<String>?) = 0
}

class ExportedUserProvider : StubProvider()
class ExportedCredentialsProvider : StubProvider()
class ExportedMessagesProvider : StubProvider()
class ExportedContactsProvider : StubProvider()
class ExportedFilesProvider : StubProvider()
class ExportedConfigProvider : StubProvider()
class ExportedTokenProvider : StubProvider()
class ExportedDatabaseProvider : StubProvider()
