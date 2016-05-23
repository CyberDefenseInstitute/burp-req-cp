package burp;

import java.util.LinkedList;
import java.util.List;
import javax.swing.JMenuItem;

import cdi.MenuItem;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
	private static final String EXTENSTION_NAME = "request copier";
	private IBurpExtenderCallbacks callbacks;

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.callbacks.setExtensionName(EXTENSTION_NAME);
		this.callbacks.registerContextMenuFactory(this);
	}

	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		IHttpRequestResponse[] httpRequestResponses = invocation.getSelectedMessages();
		if (null == httpRequestResponses) {
			return null;
		}

		JMenuItem menuItem = new JMenuItem(
				(httpRequestResponses.length > 1) ? "Copy Requests（・ω・）" : "Copy Request");
		menuItem.addMouseListener(new MenuItem(this.callbacks, httpRequestResponses));

		List<JMenuItem> menuItems = new LinkedList<JMenuItem>();
		menuItems.add(menuItem);

		return menuItems;
	}
}
