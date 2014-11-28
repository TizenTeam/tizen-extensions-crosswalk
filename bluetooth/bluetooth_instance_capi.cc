// Copyright (c) 2014 Intel Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bluetooth/bluetooth_instance_capi.h"

#include "common/picojson.h"

namespace {

inline const char* BoolToString(bool b) {
  return b ? "true" : "false";
}

}  // anonymous namespace

// Macros interfacing with C code from Bluetooth API.
#define CAPI(fnc, msg)                                                         \
  do {                                                                         \
    int _er = (fnc);                                                           \
    if (_er != BT_ERROR_NONE) {                                                \
      LOG_ERR(#fnc " failed with error: " << _er);                             \
      PostError(msg.get("reply_id").to_str(), _er);                            \
      return;                                                                  \
    }                                                                          \
    StoreReplyId(msg);                                                         \
  } while (0)

// same CAPI macro for sync messages
#define CAPI_SYNC(fnc, instance)                                               \
  do {                                                                         \
    int _er = (fnc);                                                           \
    if (_er != BT_ERROR_NONE) {                                                \
      LOG_ERR(#fnc " failed with error: " << _er);                             \
      instance->SendSyncError(_er);                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)

BluetoothInstance::BluetoothInstance()
    : get_default_adapter_(false),
      stop_discovery_from_js_(false) {
}

BluetoothInstance::~BluetoothInstance() {
  // unregister CAPI bluetooth callbacks and deinitialize
  bt_adapter_unset_state_changed_cb();
  bt_adapter_unset_name_changed_cb();
  bt_adapter_unset_visibility_mode_changed_cb();
  bt_adapter_unset_device_discovery_state_changed_cb();
  bt_device_unset_bond_created_cb();
  bt_device_unset_bond_destroyed_cb();
  bt_socket_unset_connection_state_changed_cb();
  bt_socket_unset_data_received_cb();
  bt_hdp_unset_connection_state_changed_cb();
  bt_hdp_unset_data_received_cb();
  bt_deinitialize();
}

void BluetoothInstance::Initialize() {
  // Initialize bluetooth CAPI and register all needed callbacks
  bt_initialize();
  bt_adapter_set_state_changed_cb(OnStateChanged, this);
  bt_adapter_set_name_changed_cb(OnNameChanged, this);
  bt_adapter_set_visibility_mode_changed_cb(OnVisibilityChanged, this);
  bt_adapter_set_device_discovery_state_changed_cb(OnDiscoveryStateChanged,
                                                   this);
  bt_device_set_bond_created_cb(OnBondCreated, this);
  bt_device_set_bond_destroyed_cb(OnBondDestroyed, this);
  bt_socket_set_connection_state_changed_cb(OnSocketConnected, this);
  bt_socket_set_data_received_cb(OnSocketHasData, this);
  bt_hdp_set_connection_state_changed_cb(OnHdpConnected,
                                         OnHdpDisconnected,
                                         this);
  bt_hdp_set_data_received_cb(OnHdpDataReceived, this);
}

void BluetoothInstance::HandleMessage(const char* message) {
  picojson::value v;

  std::string err;
  picojson::parse(v, message, message + strlen(message), &err);
  if (!err.empty()) {
    LOG_ERR("Ignoring message");
    return;
  }

  std::string cmd = v.get("cmd").to_str();
  if (cmd == "DiscoverDevices")
    HandleDiscoverDevices(v);
  else if (cmd == "StopDiscovery")
    HandleStopDiscovery(v);
  else if (cmd == "SetAdapterProperty")
    HandleSetAdapterProperty(v);
  else if (cmd == "CreateBonding")
    HandleCreateBonding(v);
  else if (cmd == "DestroyBonding")
    HandleDestroyBonding(v);
  else if (cmd == "RFCOMMListen")
    HandleRFCOMMListen(v);
  else if (cmd == "ConnectToService")
    HandleConnectToService(v);
  else if (cmd == "CloseSocket")
    HandleCloseSocket(v);
  else if (cmd == "UnregisterServer")
    HandleUnregisterServer(v);
  else if (cmd == "RegisterSinkApp")
    HandleRegisterSinkApp(v);
  else if (cmd == "UnregisterSinkApp")
    HandleUnregisterSinkApp(v);
  else if (cmd == "ConnectToSource")
    HandleConnectToSource(v);
  else if (cmd == "DisconnectSource")
    HandleDisconnectSource(v);
  else if (cmd == "SendHealthData")
    HandleSendHealthData(v);
}

void BluetoothInstance::HandleSyncMessage(const char* message) {
  picojson::value v;

  std::string err;
  picojson::parse(v, message, message + strlen(message), &err);
  if (!err.empty()) {
    LOG_ERR("Ignoring Sync message.");
    return;
  }

  std::string cmd = v.get("cmd").to_str();
  if (cmd == "GetDefaultAdapter")
    HandleGetDefaultAdapter(v);
  else if (cmd == "SocketWriteData")
    HandleSocketWriteData(v);
}

void BluetoothInstance::OnStateChanged(int result,
    bt_adapter_state_e adapter_state, void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  if (obj->get_default_adapter_) {
    obj->GetDefaultAdapter(obj);
    return;
  }

  picojson::value::object o;
  o["Powered"] = picojson::value(
      BoolToString(adapter_state == BT_ADAPTER_ENABLED));
  obj->PostResult("AdapterUpdated", obj->callbacks_id_map_["Powered"], result,
      o);
  obj->RemoveReplyId("Powered");
}

void BluetoothInstance::OnNameChanged(char* name, void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  picojson::value::object o;
  o["Name"] = picojson::value(name);
  obj->PostResult("AdapterUpdated", obj->callbacks_id_map_["Name"],
      BT_ERROR_NONE, o);
  obj->RemoveReplyId("Name");
}

void BluetoothInstance::OnVisibilityChanged(int result,
    bt_adapter_visibility_mode_e visibility_mode, void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  const char* visible =
      (visibility_mode == BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE) ?
          "false" : "true";

  picojson::value::object o;
  o["Discoverable"] = picojson::value(visible);
  obj->PostResult("AdapterUpdated", obj->callbacks_id_map_["Discoverable"],
      result, o);
  obj->RemoveReplyId("Discoverable");
}

void BluetoothInstance::OnDiscoveryStateChanged(int result,
    bt_adapter_device_discovery_state_e discovery_state,
    bt_adapter_device_discovery_info_s* discovery_info, void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  switch (discovery_state) {
    case BT_ADAPTER_DEVICE_DISCOVERY_STARTED: {
      obj->PostResult("", obj->callbacks_id_map_["DiscoverDevices"], result);
      obj->RemoveReplyId("DiscoverDevices");
      break;
    }
    case BT_ADAPTER_DEVICE_DISCOVERY_FINISHED: {
      if (obj->stop_discovery_from_js_) {
        obj->PostResult("", obj->callbacks_id_map_["StopDiscovery"], result);
        obj->RemoveReplyId("StopDiscovery");
      } else {
        picojson::value::object o;
        // discovery stop was not initiated by JS. It was done by a timeout...
        o["cmd"] = picojson::value("DiscoveryFinished");
        obj->PostResult("DiscoveryFinished", "", BT_ERROR_NONE);
      }
      obj->stop_discovery_from_js_ = false;
      break;
    }
    case BT_ADAPTER_DEVICE_DISCOVERY_FOUND: {
      picojson::value::object o;
      o["Alias"] = picojson::value(discovery_info->remote_name);
      o["Address"] = picojson::value(discovery_info->remote_address);

      int major = discovery_info->bt_class.major_device_class;
      int minor = discovery_info->bt_class.minor_device_class;
      int service_class = discovery_info->bt_class.major_service_class_mask;
      o["ClassMajor"] = picojson::value(static_cast<double>(major));
      o["ClassMinor"] = picojson::value(static_cast<double>(minor));
      o["ClassService"] = picojson::value(static_cast<double>(service_class));

      picojson::array uuids;
      for (int i = 0; i < discovery_info->service_count; i++)
        uuids.push_back(picojson::value(discovery_info->service_uuid[i]));

      o["UUIDs"] = picojson::value(uuids);

      bool paired = false;
      bool trusted = false;
      bool connected = false;

      if (discovery_info->is_bonded) {
        bt_device_info_s* device_info = NULL;
        bt_adapter_get_bonded_device_info(discovery_info->remote_address,
                                          &device_info);
        if (!device_info)
          LOG_ERR("device_info is NULL");

        if (!device_info->is_bonded)
          LOG_ERR("remote device should be bonded!");

        paired = true;
        trusted = device_info->is_authorized;
        connected = device_info->is_connected;
        bt_adapter_free_device_info(device_info);
      }

      o["Paired"] = picojson::value(BoolToString(paired));
      o["Trusted"] = picojson::value(BoolToString(trusted));
      o["Connected"] = picojson::value(BoolToString(connected));

      o["cmd"] = picojson::value("DeviceFound");
      o["found_on_discovery"] = picojson::value(true);
      obj->PostResult("DeviceFound", "", BT_ERROR_NONE, o);
      break;
    }
    case BT_ADAPTER_DEVICE_DISCOVERY_REMOVED: {
      picojson::value::object o;
      o["Address"] = picojson::value(discovery_info->remote_address);
      obj->PostResult("DeviceRemoved", "", BT_ERROR_NONE, o);
      break;
    }
    default:
      LOG_ERR("Unknown discovery state callback!");
      break;
  }
}

bool BluetoothInstance::OnKnownBondedDevice(bt_device_info_s* device_info,
    void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  if (!device_info)
    LOG_ERR("device_info is NULL!");

  picojson::value::object o;
  char* alias = device_info->remote_name;
  o["Alias"] = picojson::value(alias);

  char* address = device_info->remote_address;
  o["Address"] = picojson::value(address);

  int major = device_info->bt_class.major_device_class;
  int minor = device_info->bt_class.minor_device_class;
  int service_class = device_info->bt_class.major_service_class_mask;
  o["ClassMajor"] = picojson::value(static_cast<double>(major));
  o["ClassMinor"] = picojson::value(static_cast<double>(minor));
  o["ClassService"] = picojson::value(static_cast<double>(service_class));

  // parse UUIDs supported by remote device
  picojson::array uuids;
  for (int i = 0; i < device_info->service_count; i++)
    uuids.push_back(picojson::value(device_info->service_uuid[i]));

  o["UUIDs"] = picojson::value(uuids);
  o["Paired"] = picojson::value(BoolToString(device_info->is_bonded));
  o["Trusted"] = picojson::value(BoolToString(device_info->is_authorized));
  o["Connected"] = picojson::value(BoolToString(device_info->is_connected));
  obj->PostResult("BondedDevice", "", BT_ERROR_NONE, o);
  return true;
}

void BluetoothInstance::OnBondCreated(int result, bt_device_info_s* device_info,
    void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  if (!device_info)
    LOG_ERR("device_info is NULL!");

  picojson::value::object o;
  o["capi"] = picojson::value(true);
  obj->PostResult("", obj->callbacks_id_map_["CreateBonding"], result, o);
  obj->RemoveReplyId("CreateBonding");
}

void BluetoothInstance::OnBondDestroyed(int result, char* remote_address,
    void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  if (!remote_address)
    LOG_ERR("remote_address is NULL!");

  picojson::value::object o;
  o["capi"] = picojson::value(true);
  obj->PostResult("", obj->callbacks_id_map_["DestroyBonding"], result, o);
  obj->RemoveReplyId("DestroyBonding");
}

void BluetoothInstance::OnSocketConnected(int result,
    bt_socket_connection_state_e connection_state,
    bt_socket_connection_s* connection,
    void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  if (!connection)
    LOG_ERR("connection is NULL!");

  if (connection_state == BT_SOCKET_CONNECTED &&
      connection->local_role == BT_SOCKET_SERVER) {
    picojson::value::object o;
    o["uuid"] = picojson::value(connection->service_uuid);
    o["socket_fd"] =
        picojson::value(static_cast<double>(connection->socket_fd));
    o["peer"] = picojson::value(connection->remote_address);
    obj->socket_connected_map_[connection->socket_fd] = true;
    obj->PostResult("RFCOMMSocketAccept", "", BT_ERROR_NONE, o);

  } else if (connection_state == BT_SOCKET_CONNECTED &&
             connection->local_role == BT_SOCKET_CLIENT) {
    picojson::value::object o;
    o["uuid"] = picojson::value(connection->service_uuid);
    o["socket_fd"] =
        picojson::value(static_cast<double>(connection->socket_fd));
    o["peer"] = picojson::value(connection->remote_address);
    obj->socket_connected_map_[connection->socket_fd] = true;
    obj->PostResult("", obj->callbacks_id_map_["ConnectToService"], result, o);
    obj->RemoveReplyId("ConnectToService");

  } else if (connection_state == BT_SOCKET_DISCONNECTED) {
    picojson::value::object o;
    o["socket_fd"] =
        picojson::value(static_cast<double>(connection->socket_fd));
    obj->socket_connected_map_[connection->socket_fd] = false;
    obj->PostResult("", obj->callbacks_id_map_["RFCOMMsocketDestroy"], result,
        o);
    obj->RemoveReplyId("RFCOMMsocketDestroy");
  } else {
    LOG_ERR("Unknown role!");
  }
}

void BluetoothInstance::OnSocketHasData(bt_socket_received_data_s* data,
                                        void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  if (!data)
    LOG_ERR("data is NULL");

  picojson::value::object o;
  o["socket_fd"] = picojson::value(static_cast<double>(data->socket_fd));
  o["data"] = picojson::value(static_cast<std::string>(data->data));
  obj->PostResult("SocketHasData", "", BT_ERROR_NONE, o);
}

void BluetoothInstance::OnHdpConnected(int result, const char* remote_address,
    const char* app_id, bt_hdp_channel_type_e type, unsigned int channel,
    void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  picojson::value::object o;
  o["address"] = picojson::value(remote_address);
  o["app_id"] = picojson::value(app_id);
  o["channel_type"] = picojson::value(static_cast<double>(type));
  o["channel"] = picojson::value(static_cast<double>(channel));
  o["connected"] = picojson::value("true");
  obj->PostResult("", obj->callbacks_id_map_["ConnectToSource"], result, o);
  obj->RemoveReplyId("ConnectToSource");
}

void BluetoothInstance::OnHdpDisconnected(int result,
    const char* remote_address, unsigned int channel, void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  picojson::value::object o;
  o["address"] = picojson::value(remote_address);
  o["channel"] = picojson::value(static_cast<double>(channel));
  o["connected"] = picojson::value("false");
  obj->PostResult("", obj->callbacks_id_map_["DisconnectSource"], result, o);
  obj->RemoveReplyId("DisconnectSource");
}

void BluetoothInstance::OnHdpDataReceived(unsigned int channel,
    const char* data, unsigned int size, void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  picojson::value::object o;
  o["channel"] = picojson::value(static_cast<double>(channel));
  o["data"] = picojson::value(data);
  o["size"] = picojson::value(static_cast<double>(size));
  obj->PostResult("", obj->callbacks_id_map_["SendHealthData"], BT_ERROR_NONE,
      o);
  obj->RemoveReplyId("SendHealthData");
}

void BluetoothInstance::GetDefaultAdapter(void* user_data) {
  BluetoothInstance* obj = static_cast<BluetoothInstance*>(user_data);

  char* name = NULL;
  CAPI_SYNC(bt_adapter_get_name(&name), obj);

  char* address = NULL;
  CAPI_SYNC(bt_adapter_get_address(&address), obj);

  bt_adapter_state_e state = BT_ADAPTER_DISABLED;
  CAPI_SYNC(bt_adapter_get_state(&state), obj);

  bool powered = false;
  bool visible = false;

  if (state == BT_ADAPTER_ENABLED) {
    powered = true;
    bt_adapter_visibility_mode_e mode =
        BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE;

    CAPI_SYNC(bt_adapter_get_visibility(&mode, NULL), obj);
    visible = (mode > 0) ? true : false;
  }

  picojson::value::object o;
  o["name"] = picojson::value(name);
  o["address"] = picojson::value(address);
  o["powered"] = picojson::value(powered);
  o["visible"] = picojson::value(visible);
  picojson::value v(o);
  obj->SendSyncReply(v.serialize().c_str());

  // Retrieve already bonded devices linked to the adapter in order to
  // fill known_devices array on javascript side.
  bt_adapter_foreach_bonded_device(OnKnownBondedDevice, obj);

  obj->get_default_adapter_ = false;
}

void BluetoothInstance::HandleGetDefaultAdapter(const picojson::value& msg) {
  get_default_adapter_ = true;
  bt_adapter_state_e state = BT_ADAPTER_DISABLED;
  CAPI_SYNC(bt_adapter_get_state(&state), this);

  // Most of the C API functions require as precondition to previously had
  // called bt_adapter_enable(). So if adapter is turned OFF, we enable it.
  if (state == BT_ADAPTER_DISABLED) {
    CAPI_SYNC(bt_adapter_enable(), this);
    return;
  }

  GetDefaultAdapter(this);
}

void BluetoothInstance::HandleSetAdapterProperty(const picojson::value& msg) {
  if (msg.get("property").to_str() == "Powered") {
    if (msg.get("value").get<bool>())
      CAPI(bt_adapter_enable(), msg);
    else
      CAPI(bt_adapter_disable(), msg);
    goto done;
  }

  if (msg.get("property").to_str() == "Name") {
    CAPI(bt_adapter_set_name(msg.get("value").to_str().c_str()), msg);
    goto done;
  }

  if (msg.get("property").to_str() == "Discoverable") {
    bool visible = msg.get("value").get<bool>();
    int timeout = static_cast<int>(msg.get("timeout").get<double>());

    bt_adapter_visibility_mode_e discoverable_mode =
        BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE;
    if (visible) {
      if (timeout == 0)
        discoverable_mode = BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE;
      else
        discoverable_mode = BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE;
    }
    CAPI(bt_adapter_set_visibility(discoverable_mode, timeout), msg);
  }

done:
  // All adapter properties use the same json cmd, so in this case we pair the
  // property name with the reply_id.
  callbacks_id_map_[msg.get("property").to_str()] =
      callbacks_id_map_[msg.get("cmd").to_str()];
  RemoveReplyId(msg.get("cmd").to_str());
}

void BluetoothInstance::HandleDiscoverDevices(const picojson::value& msg) {
  CAPI(bt_adapter_start_device_discovery(), msg);
}

void BluetoothInstance::HandleStopDiscovery(const picojson::value& msg) {
  bool is_discovering = false;
  bt_adapter_is_discovering(&is_discovering);
  if (!is_discovering) {
    PostResult("", msg.get("reply_id").to_str(), BT_ERROR_NONE);
    return;
  }
  stop_discovery_from_js_ = true;
  CAPI(bt_adapter_stop_device_discovery(), msg);
}

void BluetoothInstance::HandleCreateBonding(const picojson::value& msg) {
  CAPI(bt_device_create_bond(msg.get("address").to_str().c_str()), msg);
}

void BluetoothInstance::HandleDestroyBonding(const picojson::value& msg) {
  CAPI(bt_device_destroy_bond(msg.get("address").to_str().c_str()), msg);
}

void BluetoothInstance::HandleRFCOMMListen(const picojson::value& msg) {
  int socket_fd = 0;
  CAPI(bt_socket_create_rfcomm(msg.get("uuid").to_str().c_str(), &socket_fd),
      msg);

  socket_connected_map_[socket_fd] = false;

  CAPI(bt_socket_listen_and_accept_rfcomm(socket_fd, 0), msg);

  picojson::value::object o;
  // give the listened socket to JS and store it in service_handler
  o["server_fd"] = picojson::value(static_cast<double>(socket_fd));
  PostResult("", msg.get("reply_id").to_str(), BT_ERROR_NONE, o);
}

void BluetoothInstance::HandleConnectToService(const picojson::value& msg) {
  CAPI(bt_socket_connect_rfcomm(msg.get("address").to_str().c_str(),
                                msg.get("uuid").to_str().c_str()),
                                msg);
}

void BluetoothInstance::HandleSocketWriteData(const picojson::value& msg) {
  std::string data = msg.get("data").to_str();
  int socket = static_cast<int>(msg.get("socket_fd").get<double>());

  CAPI_SYNC(bt_socket_send_data(socket, data.c_str(),
                                static_cast<int>(data.size())), this);

  picojson::value::object o;
  o["size"] = picojson::value(static_cast<double>(data.size()));
//  InternalSetSyncReply(picojson::value(o));
  picojson::value v(o);
  SendSyncReply(v.serialize().c_str());
}

void BluetoothInstance::HandleCloseSocket(const picojson::value& msg) {
  int socket = static_cast<int>(msg.get("socket_fd").get<double>());
  CAPI(bt_socket_disconnect_rfcomm(socket), msg);
  picojson::value::object o;
  o["capi"] = picojson::value(true);
  PostResult("", msg.get("reply_id").to_str(), BT_ERROR_NONE, o);
}

void BluetoothInstance::HandleUnregisterServer(const picojson::value& msg) {
  int socket = static_cast<int>(msg.get("server_fd").get<double>());
  CAPI(bt_socket_destroy_rfcomm(socket), msg);
  // if socket is not connected, OnSocketConnected() cb won't be triggered.
  // So in that case, we send a success post message to JavaScript.
  if (socket_connected_map_[socket] == false) {
    picojson::value::object o;
    o["socket_fd"] = picojson::value(static_cast<double>(socket));
    PostResult("", msg.get("reply_id").to_str(), BT_ERROR_NONE, o);
    RemoveReplyId(msg.get("cmd").to_str());
  }
}

void BluetoothInstance::HandleRegisterSinkApp(const picojson::value& msg) {
  uint16_t data_type =
      static_cast<uint16_t>(msg.get("datatype").get<double>());

  char* app_id = NULL;
  CAPI(bt_hdp_register_sink_app(data_type, &app_id), msg);
  picojson::value::object o;
  o["app_id"] = picojson::value(app_id);
  PostResult("", msg.get("reply_id").to_str(), BT_ERROR_NONE, o);
}

void BluetoothInstance::HandleUnregisterSinkApp(const picojson::value& msg) {
  CAPI(bt_hdp_unregister_sink_app(msg.get("app_id").to_str().c_str()), msg);
  PostResult("", msg.get("reply_id").to_str(), BT_ERROR_NONE);
}

void BluetoothInstance::HandleConnectToSource(const picojson::value& msg) {
  CAPI(bt_hdp_connect_to_source(msg.get("address").to_str().c_str(),
                                msg.get("app_id").to_str().c_str()),
                                msg);
}

void BluetoothInstance::HandleDisconnectSource(const picojson::value& msg) {
  int channel = static_cast<int>(msg.get("channel").get<double>());
  CAPI(bt_hdp_disconnect(msg.get("address").to_str().c_str(), channel), msg);
}

void BluetoothInstance::HandleSendHealthData(const picojson::value& msg) {
  std::string data = msg.get("data").to_str();
  int channel = static_cast<int>(msg.get("channel").get<double>());
  CAPI(bt_hdp_send_data(channel, data.c_str(), static_cast<int>(data.size())),
       msg);
}

void BluetoothInstance::StoreReplyId(const picojson::value& msg) {
  callbacks_id_map_[msg.get("cmd").to_str()] = msg.get("reply_id").to_str();
}

void BluetoothInstance::RemoveReplyId(const std::string& cmd) {
  if (!callbacks_id_map_[cmd].empty())
    callbacks_id_map_.erase(cmd);
}

void BluetoothInstance::PostError(std::string reply_id, int error) {
  PostResult("", reply_id, error);
}

void BluetoothInstance::SendSyncError(int error) {
  picojson::value::object o;
  o["error"] = picojson::value(static_cast<double>(error));
  picojson::value v(o);
  SendSyncReply(v.serialize().c_str());
}

void BluetoothInstance::PostResult(const std::string& cmd,
                                   std::string reply_id,
                                   int error) {
  picojson::value::object o;
  o["cmd"] = picojson::value(cmd);
  o["reply_id"] = picojson::value(reply_id);
  o["error"] = picojson::value(static_cast<double>(error));
  picojson::value v(o);
  PostMessage(v.serialize().c_str());
}

void BluetoothInstance::PostResult(const std::string& cmd,
                                   std::string reply_id,
                                   int error,
                                   picojson::value::object& o) {
  o["cmd"] = picojson::value(cmd);
  o["reply_id"] = picojson::value(reply_id);
  o["error"] = picojson::value(static_cast<double>(error));
  picojson::value v(o);
  PostMessage(v.serialize().c_str());
}
