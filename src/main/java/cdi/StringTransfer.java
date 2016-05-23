package cdi;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;

public class StringTransfer implements Transferable {

	private String transStr;
	private DataFlavor[] flavor;

	public StringTransfer(String transStr) {
		this.transStr = transStr;
		this.flavor = new DataFlavor[] { DataFlavor.stringFlavor };
	}

	public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException, IOException {
		if (!this.flavor[0].equals(flavor)) {
			throw new UnsupportedFlavorException(flavor);
		}
		return this.transStr;
	}

	public DataFlavor[] getTransferDataFlavors() {
		return flavor;
	}

	public boolean isDataFlavorSupported(DataFlavor flavor) {
		return this.flavor[0].equals(flavor);
	}
}
