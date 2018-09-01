// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;

namespace Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http2
{
    public class Http2FrameReader
    {
        /* https://tools.ietf.org/html/rfc7540#section-4.1
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +=+=============================================================+
            |                   Frame Payload (0...)                      ...
            +---------------------------------------------------------------+
        */
        public const int HeaderLength = 9;

        private const int LengthOffset = 0;
        private const int TypeOffset = 3;
        private const int FlagsOffset = 4;
        private const int StreamIdOffset = 5;

        public const int SettingSize = 6; // 2 bytes for the id, 4 bytes for the value.

        // No frame type needs more than 8 bytes of additional fields. Payload data beyond the known fields is not stored in this buffer.
        private readonly byte[] _extendedHeader = new byte[HeaderLength + 8];

        public bool ReadFrame(ReadOnlySequence<byte> readableBuffer, Http2Frame frame, uint maxFrameSize, out ReadOnlySequence<byte> framePayload)
        {
            framePayload = ReadOnlySequence<byte>.Empty;

            if (readableBuffer.Length < HeaderLength)
            {
                return false;
            }

            var headerSlice = readableBuffer.Slice(0, HeaderLength);
            headerSlice.CopyTo(_extendedHeader);

            var payloadLength = (int)Bitshifter.ReadUInt24BigEndian(_extendedHeader.AsSpan(LengthOffset));
            if (payloadLength > maxFrameSize)
            {
                throw new Http2ConnectionErrorException(CoreStrings.FormatHttp2ErrorFrameOverLimit(payloadLength, maxFrameSize), Http2ErrorCode.FRAME_SIZE_ERROR);
            }

            // Make sure the whole frame is buffered
            var frameLength = HeaderLength + payloadLength;
            if (readableBuffer.Length < frameLength)
            {
                return false;
            }

            frame.PayloadLength = payloadLength;
            frame.Type = (Http2FrameType)_extendedHeader[TypeOffset];
            frame.Flags = _extendedHeader[FlagsOffset];
            frame.StreamId = (int)Bitshifter.ReadUInt31BigEndian(_extendedHeader.AsSpan(StreamIdOffset));

            var extendedHeaderLength = ReadExtendedFields(frame, readableBuffer);

            // The remaining payload minus the extra fields
            framePayload = readableBuffer.Slice(HeaderLength + extendedHeaderLength, payloadLength - extendedHeaderLength);

            return true;
        }

        private int ReadExtendedFields(Http2Frame frame, ReadOnlySequence<byte> readableBuffer)
        {
            // Copy in any extra fields for the given frame type
            var extendedHeaderLength = GetPayloadFieldsLength(frame);

            if (extendedHeaderLength > frame.PayloadLength)
            {
                throw new Http2ConnectionErrorException(
                    CoreStrings.FormatHttp2ErrorUnexpectedFrameLength(frame.Type, expectedLength: extendedHeaderLength), Http2ErrorCode.FRAME_SIZE_ERROR);
            }

            var buffer = _extendedHeader.AsSpan(HeaderLength, extendedHeaderLength);
            readableBuffer.Slice(HeaderLength, extendedHeaderLength).CopyTo(buffer);

            // Parse frame type specific fields
            switch (frame.Type)
            {
                /*
                    +---------------+
                    |Pad Length? (8)|
                    +---------------+-----------------------------------------------+
                    |                            Data (*)                         ...
                    +---------------------------------------------------------------+
                    |                           Padding (*)                       ...
                    +---------------------------------------------------------------+
                */
                case Http2FrameType.DATA: // Variable 0 or 1
                    frame.DataPadLength = frame.DataHasPadding ? buffer[0] : (byte)0;
                    break;

                /* https://tools.ietf.org/html/rfc7540#section-6.2
                    +---------------+
                    |Pad Length? (8)|
                    +-+-------------+-----------------------------------------------+
                    |E|                 Stream Dependency? (31)                     |
                    +-+-------------+-----------------------------------------------+
                    |  Weight? (8)  |
                    +-+-------------+-----------------------------------------------+
                    |                   Header Block Fragment (*)                 ...
                    +---------------------------------------------------------------+
                    |                           Padding (*)                       ...
                    +---------------------------------------------------------------+
                */
                case Http2FrameType.HEADERS:
                    if (frame.HeadersHasPadding)
                    {
                        frame.HeadersPadLength = buffer[0];
                        buffer = buffer.Slice(1);
                    }
                    else
                    {
                        frame.HeadersPadLength = 0;
                    }

                    if (frame.HeadersHasPriority)
                    {
                        frame.HeadersStreamDependency = (int)Bitshifter.ReadUInt31BigEndian(buffer);
                        frame.HeadersPriorityWeight = buffer.Slice(4)[0];
                    }
                    else
                    {
                        frame.HeadersStreamDependency = 0;
                        frame.HeadersPriorityWeight = 0;
                    }
                    break;

                /* https://tools.ietf.org/html/rfc7540#section-6.8
                    +-+-------------------------------------------------------------+
                    |R|                  Last-Stream-ID (31)                        |
                    +-+-------------------------------------------------------------+
                    |                      Error Code (32)                          |
                    +---------------------------------------------------------------+
                    |                  Additional Debug Data (*)                    |
                    +---------------------------------------------------------------+
                */
                case Http2FrameType.GOAWAY:
                    frame.GoAwayLastStreamId = (int)Bitshifter.ReadUInt31BigEndian(buffer);
                    frame.GoAwayErrorCode = (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(4));
                    break;

                /* https://tools.ietf.org/html/rfc7540#section-6.3
                    +-+-------------------------------------------------------------+
                    |E|                  Stream Dependency (31)                     |
                    +-+-------------+-----------------------------------------------+
                    |   Weight (8)  |
                    +-+-------------+
                */
                case Http2FrameType.PRIORITY:
                    frame.PriorityStreamDependency = (int)Bitshifter.ReadUInt31BigEndian(buffer);
                    frame.PriorityWeight = buffer.Slice(4)[0];
                    break;

                /* https://tools.ietf.org/html/rfc7540#section-6.4
                    +---------------------------------------------------------------+
                    |                        Error Code (32)                        |
                    +---------------------------------------------------------------+
                */
                case Http2FrameType.RST_STREAM:
                    frame.RstStreamErrorCode = (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(buffer);
                    break;

                /* https://tools.ietf.org/html/rfc7540#section-6.9
                    +-+-------------------------------------------------------------+
                    |R|              Window Size Increment (31)                     |
                    +-+-------------------------------------------------------------+
                */
                case Http2FrameType.WINDOW_UPDATE:
                    frame.WindowUpdateSizeIncrement = (int)Bitshifter.ReadUInt31BigEndian(buffer);
                    break;

                case Http2FrameType.PING: // Opaque payload 8 bytes long
                case Http2FrameType.SETTINGS: // Settings are general payload
                case Http2FrameType.CONTINUATION: // None
                case Http2FrameType.PUSH_PROMISE: // Not implemented frames are ignored at this phase
                default:
                    return 0;
            }

            return extendedHeaderLength;
        }

        // The length in bytes of additional fields stored in the payload section.
        // This may be variable based on flags, but should be no more than 8 bytes.
        public int GetPayloadFieldsLength(Http2Frame frame)
        {
            switch (frame.Type)
            {
                // TODO: Extract constants
                case Http2FrameType.DATA: // Variable 0 or 1
                    return frame.DataHasPadding ? 1 : 0;
                case Http2FrameType.HEADERS:
                    return (frame.HeadersHasPadding ? 1 : 0) + (frame.HeadersHasPriority ? 5 : 0); // Variable 0 to 6
                case Http2FrameType.GOAWAY:
                    return 8; // Last stream id and error code.
                case Http2FrameType.PRIORITY:
                    return 5; // Stream dependency and weight
                case Http2FrameType.RST_STREAM:
                    return 4; // Error code
                case Http2FrameType.WINDOW_UPDATE:
                    return 4; // Update size
                case Http2FrameType.PING: // 8 bytes of opaque data
                case Http2FrameType.SETTINGS: // Settings are general payload
                case Http2FrameType.CONTINUATION: // None
                case Http2FrameType.PUSH_PROMISE: // Not implemented frames are ignored at this phase
                default:
                    return 0;
            }
        }

        public IList<Http2PeerSetting> ReadSettings(ReadOnlySequence<byte> payload)
        {
            var data = payload.ToArray().AsSpan();
            Debug.Assert(data.Length % SettingSize == 0, "Invalid settings payload length");
            var settingsCount = data.Length / SettingSize;

            var settings = new Http2PeerSetting[settingsCount];
            for (int i = 0; i < settings.Length; i++)
            {
                settings[i] = ReadSetting(data);
                data = data.Slice(SettingSize);
            }
            return settings;
        }

        private Http2PeerSetting ReadSetting(Span<byte> payload)
        {
            var id = (Http2SettingsParameter)BinaryPrimitives.ReadUInt16BigEndian(payload);
            var value = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(2));

            return new Http2PeerSetting(id, value);
        }
    }
}
