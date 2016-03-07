/**
 *    Copyright 2013, Big Switch Networks, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/

package net.floodlightcontroller.rolechanger;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.BasePacket;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.util.OFBundle;

import org.projectfloodlight.openflow.protocol.OFAsyncGetReply;
import org.projectfloodlight.openflow.protocol.OFAsyncGetRequest;
import org.projectfloodlight.openflow.protocol.OFAsyncSet;
import org.projectfloodlight.openflow.protocol.OFBarrierReply;
import org.projectfloodlight.openflow.protocol.OFBarrierRequest;
import org.projectfloodlight.openflow.protocol.OFControllerRole;
import org.projectfloodlight.openflow.protocol.OFGetConfigReply;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketInReason;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFRoleReply;
import org.projectfloodlight.openflow.protocol.OFRoleRequest;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;

/**
 * 
 * 
 * @author
 */
public class RoleChanger implements IFloodlightModule, IOFMessageListener,
		IOFSwitchListener {

	private static OFControllerRole desiredInitialRole;
	private static String controllerId;

	private final static int RESERVED_ETH_TYPE = 65535;

	// Our dependencies
	protected IFloodlightProviderService floodlightProviderService;
	protected IRestApiService restApiService;

	private IOFSwitchService switchService;

	protected OFAsyncGetReply lastAsyncGetReply;

	private static Logger log;

	private final static boolean debug = true;

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		switch (msg.getType()) {

		case PACKET_IN:
			OFPacketIn ofpi = (OFPacketIn) msg;
			log.info("{}", getPacketInString(ofpi, sw));

			if (sw.getControllerRole().equals(OFControllerRole.ROLE_SLAVE)) {
				log.info("# Received Packet-In in slave!");
			} else if (ofpi.getReason() == OFPacketInReason.PACKET_OUT
					|| ofpi.getReason() == OFPacketInReason.ACTION) {
				log.info("# Received Packet-In from Packet-Out");
			} else if (!getInPort(ofpi).equals(OFPort.CONTROLLER)) {
				String s = "hello from controller " + controllerId;
				sendTestPacketOut(sw, s.getBytes());
			}
			return Command.CONTINUE;

		case PACKET_OUT:
			OFPacketOut pout = (OFPacketOut) msg;
			Ethernet eth = new Ethernet();
			eth.deserialize(pout.getData(), 0, pout.getData().length);
			short type = (short) eth.getEtherType().getValue();
			if (type != Ethernet.TYPE_LLDP && type != Ethernet.TYPE_BSN)
				log.info("{}", getPacketOutString(pout, eth, sw));
			return Command.CONTINUE;

		case BARRIER_REPLY:
			log.info("Received BARRIER_REPLY");
			log.info("Barrier reply xid: {}", msg.getXid());
			sendTestPacketOut(sw, "test string 2".getBytes());
			return Command.CONTINUE;

		case ROLE_REPLY:
			log.info("Received ROLE_REPLY");
			// sendBarrier(sw);
			return Command.CONTINUE;

		case GET_ASYNC_REPLY:
			OFAsyncGetReply asyncReply = (OFAsyncGetReply) msg;
			log.info("Received GET_ASYNC_REPLY: {}", asyncReply.toString());
			return Command.CONTINUE;

		case GET_CONFIG_REPLY:
			OFGetConfigReply configReply = (OFGetConfigReply) msg;
			log.info("Received GET_CONFIG_REPLY: {}", configReply.toString());
			return Command.CONTINUE;

		default:
			break;
		}
		log.warn("Received unexpected message {}", msg);
		return Command.CONTINUE;
	}

	public OFPort getInPort(OFPacketIn pi) {
		return (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT));
	}

	public String getControllerRole(IOFSwitch sw) {
		int last_ = sw.getControllerRole().name().lastIndexOf('_');
		return sw.getControllerRole().name().charAt(last_ + 1) + "";
	}

	public String getPacketOutString(OFPacketOut po, Ethernet eth, IOFSwitch sw) {
		String data = "";
		if (eth.getEtherType().getValue() == RESERVED_ETH_TYPE) {
			Data d = (Data) eth.getPayload();
			data = new String(d.getData());
		} else {
			data = eth.getEtherType() + "";
		}
		return "" + po.getType() + " | In " + po.getInPort() + " | "
				+ po.getActions() + " | From " + sw.getId() + " ("
				+ getControllerRole(sw) + ")" + " | Data: " + data;
	}

	public String getPacketInString(OFPacketIn pi, IOFSwitch sw) {
		Ethernet eth = new Ethernet();
		eth.deserialize(pi.getData(), 0, pi.getData().length);
		String data = "";
		if (eth.getEtherType().getValue() == RESERVED_ETH_TYPE) {
			Data d = (Data) eth.getPayload();
			data = new String(d.getData());
		} else {
			data = eth.getEtherType().toString();
		}
		return "" + pi.getType() + "(xid=" + pi.getXid() + ") | In "
				+ getInPort(pi) + " | " + pi.getReason() + " | "
				+ pi.getMatch() + " | From " + sw.getId() + " ("
				+ getControllerRole(sw) + ") | " + "Data: " + data;
	}

	private void sendTestPacketOut(IOFSwitch sw, byte[] data) {

		List<OFAction> actions = buildActionOutputController(sw);

		Ethernet testPacket = buildSimpleEthernetWithData(data);

		OFPacketOut out = buildPacketOut(sw, OFPort.CONTROLLER, actions,
				testPacket);

		if (debug || log.isDebugEnabled())
			log.info("{}", getOutGoingPacketOut(sw, out, data));

		sw.write(out);

	}

	private List<OFAction> buildActionOutputController(IOFSwitch sw) {
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(sw.getOFFactory().actions().buildOutput()
				.setPort(OFPort.CONTROLLER)
				// .setMaxLen(OFBufferId.NO_BUFFER.getInt()) // TODO !!!!
				.setMaxLen(0xFFFF).build());
		return actions;
	}

	private Ethernet buildSimpleEthernetWithData(byte[] data) {
		Ethernet l2 = new Ethernet();
		l2.setEtherType(EthType.of(RESERVED_ETH_TYPE));
		l2.setSourceMACAddress(MacAddress.of("00:00:00:00:00:01"));
		l2.setDestinationMACAddress(MacAddress.BROADCAST);
		Data packetData = new Data();
		packetData.setData(data);
		l2.setPayload(packetData);
		return l2;
	}

	private OFPacketOut buildPacketOut(IOFSwitch sw, OFPort inPort,
			List<OFAction> actions, BasePacket packet) {

		byte[] packetBytes = packet.serialize();

		return sw.getOFFactory().buildPacketOut()
				.setBufferId(OFBufferId.NO_BUFFER).setInPort(inPort)
				.setActions(actions).setData(packetBytes).build();
	}

	private String getOutGoingPacketOut(IOFSwitch sw, OFPacketOut out,
			byte[] data) {
		String spo = out.getType() + "(xid=" + out.getXid() + ", bufferId="
				+ out.getBufferId() + ", inPort=" + out.getInPort()
				+ ", actions=" + out.getActions() + ")";
		String s = "Sending: " + spo + " | data: " + new String(data) + " to "
				+ sw.getId().toString();
		return s;
	}

	public static void sendRoleRequest(final IOFSwitch sw, OFControllerRole role) {

		OFRoleRequest roleReq = sw.getOFFactory().buildRoleRequest()
				.setRole(role).build();

		if (debug || log.isDebugEnabled())
			log.info("Sending role request to switch {}", sw.getId().toString());

		// send role request and save ListenableFuture
		ListenableFuture<OFRoleReply> future = sw.writeRequest(roleReq);

		// add callback to execute when future computation is complete
		Futures.addCallback(future, new FutureCallback<OFRoleReply>() {

			@Override
			public void onFailure(Throwable arg0) {
				log.error("Failed to receive ROLE_REPLY from switch {}", sw
						.getId().toString());
				// sem.release();
			}

			@Override
			public void onSuccess(OFRoleReply reply) {
				log.info("Received ROLE_REPLY. Current role on switch "
						+ sw.getId().toString() + ": {}", reply.getRole()
						.toString());
				// sem.release();
			}

		});

		if (debug || log.isDebugEnabled())
			log.info("RoleRequest sent to switch " + sw.getId().toString()
					+ ". xid: {}; role: {}", roleReq.getXid(),
					roleReq.getRole());
	}

	private void sendGetAsyncRequest(final IOFSwitch sw, final Semaphore sem) {

		OFAsyncGetRequest req = sw.getOFFactory().buildAsyncGetRequest()
				.build();

		if (debug || log.isDebugEnabled())
			log.info("Sending Async Get Request to switch {}", sw.getId()
					.toString());

		// send role request and save ListenableFuture
		ListenableFuture<OFAsyncGetReply> future = sw.writeRequest(req);

		// add callback to execute when future computation is complete
		Futures.addCallback(future, new FutureCallback<OFAsyncGetReply>() {

			@Override
			public void onFailure(Throwable arg0) {
				log.error(
						"Failed to receive AsyncGetReply ({}) from switch {}: {}",
						arg0.toString(), sw.getId());
				// TODO: default last assync get reply if null
				sem.release();
			}

			@Override
			public void onSuccess(OFAsyncGetReply reply) {
				log.info("Received AsyncGetReply from switch {}: {}",
						sw.getId(), reply.toString());
				lastAsyncGetReply = reply;
				sem.release();
			}

		});

	}

	/**
	 * Sets the async properties in the switch so that slave and master receive
	 * the same async messages.
	 * 
	 * @param sw
	 * @param r
	 */
	protected static void sendSetAsync(IOFSwitch sw, OFAsyncGetReply r) {

		OFAsyncSet setConfig = sw
				.getOFFactory()
				.buildAsyncSet()
				.setPacketInMaskEqualMaster(r.getPacketInMaskEqualMaster())
				.setPacketInMaskSlave(r.getPacketInMaskEqualMaster())
				.setPortStatusMaskEqualMaster(r.getPortStatusMaskEqualMaster())
				.setPortStatusMaskSlave(r.getPortStatusMaskEqualMaster())
				.setFlowRemovedMaskEqualMaster(
						r.getFlowRemovedMaskEqualMaster())
				.setFlowRemovedMaskSlave(r.getFlowRemovedMaskEqualMaster())
				.build();

		if (debug || log.isDebugEnabled())
			log.info("Sending set async {} to switch {}", setConfig.toString(),
					sw.getId().toString());

		sw.write(setConfig);
	}

	public static void sendBarrier(final IOFSwitch sw, final Semaphore sem) {

		if (debug || log.isDebugEnabled())
			log.info("Sending barrier to switch {}", sw.getId().toString());

		OFBarrierRequest barReq = sw.getOFFactory().buildBarrierRequest()
				.build();

		// send barrier and save ListenableFuture
		ListenableFuture<OFBarrierReply> future = sw.writeRequest(barReq);

		// add callback to execute when future computation is complete
		Futures.addCallback(future, new FutureCallback<OFBarrierReply>() {

			@Override
			public void onFailure(Throwable arg0) {
				log.error("Failed to receive BARRIER_REPLY from switch "
						+ sw.getId());
				sem.release();
			}

			@Override
			public void onSuccess(OFBarrierReply reply) {
				log.info("Received BARRIER_REPLY from switch " + sw.getId()
						+ ". xid: {}", reply.getXid());
				sem.release();
			}

		});

		if (debug || log.isDebugEnabled())
			log.info("BARRIER_REQUEST sent. xid: {}", barReq.getXid());

	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProviderService = context
				.getServiceImpl(IFloodlightProviderService.class);

		switchService = context.getServiceImpl(IOFSwitchService.class);

		log = LoggerFactory.getLogger(RoleChanger.class);

		Map<String, String> configOptions = context.getConfigParams(this);

		// set current role for initial role in config file
		String role = configOptions.get("initialRole");
		if (role != null)
			desiredInitialRole = OFControllerRole.valueOf("ROLE_" + role);
		else
			desiredInitialRole = OFControllerRole.ROLE_EQUAL;
		
		controllerId = configOptions.get("controllerId");
		if (controllerId == null)
			controllerId = "c";

		if (debug || log.isDebugEnabled())
			log.info("Initial Role for switches: {}", desiredInitialRole);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProviderService.addOFMessageListener(OFType.BARRIER_REPLY,
				this);
		floodlightProviderService.addOFMessageListener(OFType.ROLE_REPLY, this);
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		// floodlightProviderService.addOFMessageListener(OFType.PACKET_OUT,
		// this);
		floodlightProviderService.addOFMessageListener(OFType.GET_ASYNC_REPLY,
				this);
		floodlightProviderService.addOFMessageListener(OFType.GET_CONFIG_REPLY,
				this);
		switchService.addOFSwitchListener(this);
	}

	@Override
	public void switchAdded(DatapathId switchId) {

	}

	@Override
	public void switchRemoved(DatapathId switchId) {

	}

	@Override
	public void switchActivated(DatapathId switchId) {

		final IOFSwitch sw = switchService.getSwitch(switchId);

		if (debug || log.isDebugEnabled())
			log.info("New switch added: {}; Role on switch: {} ",
					switchId.toString(), sw.getControllerRole().toString());

		if (sw.getControllerRole() != desiredInitialRole) {
			sendRoleRequest(sw, desiredInitialRole);
			if (desiredInitialRole == OFControllerRole.ROLE_SLAVE) {
				setSlaveAsyncConfig(sw);
			}
		}

	}

	private void setSlaveAsyncConfig(IOFSwitch sw) {
		final Semaphore sem = new Semaphore(0);
		try {
			sendBarrier(sw, sem); // sem = 1 after receive

			// sem unlocked means barrier reply was received
			sem.acquire(); // sem = 0

			sendGetAsyncRequest(sw, sem); // sem = 1 after receive

			// sem unlocked means async reply was received
			sem.acquire(); // sem = 0

			sendSetAsync(sw, lastAsyncGetReply);

			sendGetAsyncRequest(sw, sem); // sem = 1 after receive

		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port,
			PortChangeType type) {

	}

	@Override
	public void switchChanged(DatapathId switchId) {

	}

	@Override
	public String getName() {
		return "rolechanger";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		if (type.equals(OFType.PACKET_IN)) {
			return true;
		} else {
			return false;
		}
	}
}