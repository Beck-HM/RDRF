namespace RDRF.Core.Compression.Ckc;

internal sealed class CkcStateMachine
{
    private int _state;
    private readonly int[] _rep = new int[4];

    public int State => _state;
    public int Rep0 => _rep[0];
    public int Rep1 => _rep[1];
    public int Rep2 => _rep[2];
    public int Rep3 => _rep[3];

    public void Reset()
    {
        _state = 0;
        _rep[0] = _rep[1] = _rep[2] = _rep[3] = -1;
    }

    public void OnLiteral()
    {
        _state = _state switch
        {
            < 4 => 0,
            4 => 1, 5 => 2, 6 => 3,
            7 => 4, 8 => 5, 9 => 6,
            10 => 4, 11 => 5,
            _ => 0
        };
    }

    public void OnNormalMatch(int distance)
    {
        _rep[3] = _rep[2]; _rep[2] = _rep[1]; _rep[1] = _rep[0]; _rep[0] = distance;
        _state = _state < 7 ? 7 : 10;
    }

    public void OnLongRep(int repIndex)
    {
        int dist = _rep[repIndex];
        if (repIndex > 0)
        {
            // Move used rep to front
            for (int i = repIndex; i > 0; i--)
                _rep[i] = _rep[i - 1];
            _rep[0] = dist;
        }
        _state = _state < 7 ? 8 : 11;
    }

    public void OnShortRep()
    {
        _state = _state < 7 ? 9 : 11;
    }

    public (int state, int r0, int r1, int r2, int r3) Snapshot()
        => (_state, _rep[0], _rep[1], _rep[2], _rep[3]);

    public void Restore(int state, int r0, int r1, int r2, int r3)
    {
        _state = state;
        _rep[0] = r0; _rep[1] = r1; _rep[2] = r2; _rep[3] = r3;
    }

    public bool IsRep0(int distance) => distance == _rep[0];
    public bool IsRep1(int distance) => distance == _rep[1];
    public bool IsRep2(int distance) => distance == _rep[2];
    public bool IsRep3(int distance) => distance == _rep[3];

    public int WhichRep(int distance)
    {
        if (distance == _rep[0]) return 0;
        if (distance == _rep[1]) return 1;
        if (distance == _rep[2]) return 2;
        if (distance == _rep[3]) return 3;
        return -1;
    }
}
