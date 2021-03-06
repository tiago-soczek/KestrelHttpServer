// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http2
{
    /* https://tools.ietf.org/html/rfc7540#section-6.9
        +-+-------------------------------------------------------------+
        |R|              Window Size Increment (31)                     |
        +-+-------------------------------------------------------------+
    */
    public partial class Http2Frame
    {
        public int WindowUpdateSizeIncrement
        {
            get => (int)Bitshifter.ReadUInt31BigEndian(Payload);
            set => Bitshifter.WriteUInt31BigEndian(Payload, (uint)value);
        }

        public void PrepareWindowUpdate(int streamId, int sizeIncrement)
        {
            PayloadLength = 4;
            Type = Http2FrameType.WINDOW_UPDATE;
            Flags = 0;
            StreamId = streamId;
            WindowUpdateSizeIncrement = sizeIncrement;
        }
    }
}
